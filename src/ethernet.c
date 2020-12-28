#include "ethernet.h"
#include "utils.h"
#include "driver.h"
#include "arp.h"
#include "ip.h"
#include <string.h>
#include <stdio.h>

//处理MAC的大小端转换单个字节内部不反，多个字节之间的顺序要反
/*void processMAC(uint8_t *mac_data){
    uint8_t temp_MAC[6];    //暂存数值，稍后写回指针位置
    uint8_t *temp_mac_data = mac_data;  //暂存指针
    for(int i = 5; i >= 0; i--){
        temp_MAC[i] = temp_mac_data[0];
        temp_mac_data++;
    } //从结尾开始存，这样就倒过来了，然后写
    temp_mac_data = mac_data;   //由于指针为常量，所以要用这个暂存指针来操作
    for(int i = 0; i < 6; i++){
        temp_mac_data[0] = temp_MAC[i];
        temp_mac_data++;
    }  //写回
}   不用转换MAC地址*/

/**
 * @brief 处理一个收到的数据包
 *        你需要判断以太网数据帧的协议类型，注意大小端转换
 *        如果是ARP协议数据包，则去掉以太网包头，发送到arp层处理arp_in()
 *        如果是IP协议数据包，则去掉以太网包头，发送到IP层处理ip_in()
 * 
 * @param buf 要处理的数据包
 */
void ethernet_in(buf_t *buf)
{
    uint8_t *temp = buf->data + 12;
    uint16_t *type = (void *) temp; //协议类型号
    *type = swap16(*type);   //大小端转换
    buf_remove_header(buf, 14); //去以太网帧头
    if(*type == 0x0806)
        arp_in(buf);   //是arp协议，放进这个函数处理该数据帧
    else if(*type == 0x0800)   //是ip协议，调用相关函数处理
        ip_in(buf); //实验3不需要实现底层，那是后面实现的
}

/**
 * @brief 处理一个要发送的数据包
 *        你需添加以太网包头，填写目的MAC地址、源MAC地址、协议类型
 *        添加完成后将以太网数据帧发送到驱动层
 * 
 * @param buf 要处理的数据包
 * @param mac 目标ip地址（是指针的起点，需要遍历取出所有MAC）
 * @param protocol 上层协议
 */
void ethernet_out(buf_t *buf, const uint8_t *mac, net_protocol_t protocol)
{
    buf_add_header(buf,sizeof(ether_hdr_t));
    ether_hdr_t* head = (ether_hdr_t*)buf->data;
    uint8_t src[NET_MAC_LEN] = DRIVER_IF_MAC;
    uint16_t i;
    for(i=0;i<NET_MAC_LEN;i++){
        head->src[i] = src[i];
        head->dest[i] = mac[i];
    }
    head->protocol = swap16(protocol);
    driver_send(buf);
}

/**
 * @brief 初始化以太网协议
 * 
 * @return int 成功为0，失败为-1
 */
int ethernet_init()
{
    buf_init(&rxbuf, ETHERNET_MTU + sizeof(ether_hdr_t));
    return driver_open();
}

/**
 * @brief 一次以太网轮询
 * 
 */
void ethernet_poll()
{
    if (driver_recv(&rxbuf) > 0)
        ethernet_in(&rxbuf);
}
