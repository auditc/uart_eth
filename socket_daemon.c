#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <termios.h>

//#define DEBUG

#ifdef DEBUG
	#define dbg_print(...) fprintf(stdout, __VA_ARGS__)
	#define dbg_write(fd, buf, size) write(fd, buf, size)
#else
	#define dbg_print(...) 
	#define dbg_write(fd, buf, size)
#endif

#define FILE_PATH_LEN 256
#define UART_ETH_HEAD "uart_eth:"

struct eth_daemon_priv {
	int eth_fd;
	int uart_fd;
	char eth_file_path[FILE_PATH_LEN];
	char uart_file_path[FILE_PATH_LEN];
	pthread_t tx_thread_id;
	pthread_t rx_thread_id;
	pthread_mutex_t mutex;
	int uart_reconnetcing;
};

int uart_init(struct eth_daemon_priv *priv);


void usage(char *filename)
{
	printf("Usage:\n");
	printf("%s <ETH_FILE_PATH> <UART_PATH>\n", filename);
}

void restart_uart(struct eth_daemon_priv *priv)
{
	int try = 0;
	int uart_fd;
	int ret;

	pthread_mutex_lock(&priv->mutex);
	if(priv->uart_reconnetcing){
		pthread_mutex_unlock(&priv->mutex);
		sleep(5);
		return;
	}

	close(priv->uart_fd);
	
	priv->uart_reconnetcing = 1;
	pthread_mutex_unlock(&priv->mutex);

	while(try++ < 10){
		printf("trying to restart uart time %d ...\n", try);
		
		ret = uart_init(priv);
		if(!ret) {
			printf("uart restart success\n");
			return;
		}
		sleep(3);
	}

	printf("uart restart failed.\n");
}

void * uart_tx_thread(void *arg)
{
	struct eth_daemon_priv *priv = arg;
	int eth_fd = priv->eth_fd;
	int uart_fd = priv->uart_fd;
	char buf[2000];
	int len;

	printf("%s", __func__);

	for(;;){
		len = read(eth_fd, buf, sizeof(buf));
		dbg_print("read %d bytes from eth file\n", len);
		if(len < 0){
			printf("%s, eth_fd reach end of file or encounter a error\n", __func__);
			continue;
		}
		
		for(int i = 0; i < len; i++)
			dbg_print("%02x ", buf[i]);
		dbg_print("\n");
		write(uart_fd, buf, len);
		if(len < 0){
			dbg_print("%s, uart_rx reach end of file or encounter a error, trying to reconnect uart...\n", __func__);
			restart_uart(priv);
		}
		dbg_print("write %d bytes to uart\n", len);
	}
}

void * uart_rx_thread(void *arg)
{
	struct eth_daemon_priv *priv = arg;
	int eth_fd = priv->eth_fd;
	int uart_fd = priv->uart_fd;
	char buf[2000] = {0};
	char data_buf[2000] = {0};
	int len;
	uint16_t packet_len;
	char *pos;
	int has_remain_data = 0;
	int remain_bytes;
	int copyed_bytes;

	printf("%s", __func__);

	for(;;){
		len = read(uart_fd, buf, sizeof(buf));
		if(len < 0){
			printf("\n%s, uart_rx reach end of file or encounter a error, trying to reconnect uart...\n", __func__);
			restart_uart(priv);
		}

		dbg_print("\nread %d bytes from uart\n", len);
		for(int i = 0; i < len; i++)
			dbg_print("%02x ", buf[i]);
		dbg_print("\n");
		buf[len] = '\0';
		pos = buf;
		if(has_remain_data){
			dbg_print("\nhas_remain_data = %d\n", has_remain_data);
			if(remain_bytes > len){
				dbg_print("packet incomplete\n");
				memcpy(data_buf + copyed_bytes, pos, len);
				remain_bytes -= len;
				copyed_bytes += len;
				continue;
			}
			
			memcpy(data_buf + copyed_bytes, buf, remain_bytes);
			has_remain_data = 0;
			pos += remain_bytes;
			write(eth_fd, data_buf, packet_len);
			dbg_print("remain data receive complete\n");
			dbg_print("the complete packet is:\n");
			for(int i = 0; i < packet_len; i++)
				dbg_print("%02x ", data_buf[i]);
			dbg_print("\n");
		}
		while(pos = strstr(pos, UART_ETH_HEAD)){
			pos += strlen(UART_ETH_HEAD);
			packet_len = ntohs(*(uint16_t *)pos);
			if(packet_len > 1500)
				continue;
			dbg_print("packet_len = %d\n", packet_len);
			pos +=2;
			if((buf + len) < (pos + packet_len)){
				has_remain_data = 1;
				copyed_bytes = buf + len - pos;
				memcpy(data_buf, pos, copyed_bytes);
				remain_bytes = packet_len - copyed_bytes;

				dbg_print("packet_content:\n");
				for(int i = 0; i < copyed_bytes; i++)
					dbg_print("%02x ", pos[i]);
				dbg_print("\n");
				break;
			}

			dbg_print("packet_content:\n");
			dbg_write(1, pos, packet_len);

			dbg_print("\nwriting to eth_drv...\n");
			write(eth_fd, pos, packet_len);
			pos += packet_len;
			has_remain_data = 0;
			dbg_print("write %d bytes to eth\n", len);
		}
	}
}

int uart_init(struct eth_daemon_priv *priv)
{
	int uart_fd;
	struct termios term;
	char *uart_file_path = priv->uart_file_path;

	uart_fd = open(uart_file_path,O_RDWR);
	if(uart_fd < 0)
	{
	   printf("open a serialport failure:%s\n",strerror(errno));
	   return -1;
	}
	if(!isatty(uart_fd))
	{
	    printf("open fd is not a terminal device\n");
	    return -2;
	}
	priv->uart_fd = uart_fd;

	if(tcgetattr(uart_fd, &term) < 0){
        printf("tcgetattr failed\n");
        return -1;
    }

	
	term.c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG);
    term.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
    term.c_cflag &= ~(CSIZE | PARENB);
    term.c_cflag |= CS8;
    term.c_oflag &= ~(OPOST);
    term.c_cc[VMIN] = 1;
    term.c_cc[VTIME] = 1;
	
	if(cfsetispeed(&term,B500000) < 0)
	{
	    printf("cfsetispeed failure:%s\n",strerror(errno));
	    return -2;
	}
	if(cfsetospeed(&term,B500000) < 0)
	{
	    printf("cfsetospeed failure:%s\n",strerror(errno));
	    return -2;
	}
	//只有在输出队列为空时才能改变一个终端的属性，所以要用tcflush;
	tcflush(uart_fd,TCIFLUSH);
	if(tcsetattr(uart_fd,TCSANOW,&term) != 0)
	{
	    printf("tcsetattr failure:%s\n",strerror(errno));
	    return -2;
	}

	return 0;
}

int priv_init(struct eth_daemon_priv *priv, int argc, char *argv[])
{
	int ret;
	char *eth_file_path = priv->eth_file_path;
	char *uart_file_path = priv->uart_file_path;
	int eth_fd, uart_fd;

	strncpy(eth_file_path, argv[1], FILE_PATH_LEN);
	strncpy(uart_file_path, argv[2], FILE_PATH_LEN);

	eth_fd = open(eth_file_path,  O_RDWR);
	if(eth_fd < 0) {
		printf("%s:\n", __func__);
		printf("open %s failed", eth_file_path);
		perror("");
		return -errno;
	}
	priv->eth_fd = eth_fd;

	ret = uart_init(priv);
	if(ret < 0) {
		printf("%s:\n", __func__);
		printf("uart_init failed\n");
		perror("");
		if(ret < -1)
			close(priv->uart_fd);
		close(eth_fd);
		return -errno;
	}

	ret = pthread_mutex_init(&priv->mutex, NULL);
	if(ret){
		perror("pthread_mutex_init failed\n");
		close(eth_fd);
		close(uart_fd);
		return -errno;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int ret;
	pthread_t tx_thread_id;
	pthread_t rx_thread_id;
	struct eth_daemon_priv *priv;
	void *retval;

	if (argc < 3) {
		usage(argv[0]);
		return -1;
	}

	priv = calloc(1, sizeof(struct eth_daemon_priv));
	if(!priv){
		printf("alloc priv memory failed\n");
		return -ENOMEM;
	}

	ret = priv_init(priv, argc, argv);
	if(ret){
		printf("priv_init failed\n");
		goto free_priv;
	}
	
  	ret = pthread_create(&tx_thread_id, NULL, uart_tx_thread, priv);
	if(ret) {
		printf("uart_tx_thread pthread_create failed with error code %d\n", ret);
		goto close_files;
	}
	priv->tx_thread_id = tx_thread_id;

	ret = pthread_create(&tx_thread_id, NULL, uart_rx_thread, priv);
	if(ret) {
		printf("uart_rx_thread pthread_create failed with error code %d\n", ret);
		pthread_cancel(tx_thread_id);
		goto close_files;
	}
	priv->rx_thread_id = rx_thread_id;
	
	ret = pthread_join(tx_thread_id, &retval);
	if(ret){
		printf("pthread_join tx failed with error code %d\n", ret);
	}

	ret = pthread_join(rx_thread_id, &retval);
	if(ret){
		printf("pthread_join rx failed with error code %d\n", ret);
	}
	
close_files:
	close(priv->eth_fd);
	close(priv->uart_fd);
free_priv:
	free(priv);

	return ret;
}
