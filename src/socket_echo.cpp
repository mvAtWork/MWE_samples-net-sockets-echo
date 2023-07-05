/*
 * Copyright (c) 2017 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#ifndef __ZEPHYR__

#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#else

#include <zephyr/net/socket.h>
#include <zephyr/kernel.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_config.h>

#endif

#define BIND_PORT 4242

void custom_net_if_init()
{
    int ret;

    struct net_if *iface = net_if_get_default();
    if (!iface)
    {
        printf("device lookup failed for network interface\n");
        return;
    }
    printf("configuring network interface %s\n", iface->if_dev->dev->name);

    /* remove IPv4 address set in kconfig */
    if (sizeof(CONFIG_NET_CONFIG_MY_IPV4_ADDR) > 1)
    {
        struct in_addr defaultAddr;
        net_addr_pton(AF_INET, CONFIG_NET_CONFIG_MY_IPV4_ADDR, &defaultAddr);
        ret = net_if_ipv4_addr_rm(iface, &defaultAddr);
        printf("removal of default ip returned %i\n", ret);
    }

    /* set IPv4 address */
    const char* ipAddrStr = "192.0.77.77";
    struct in_addr ipAddr;
    ret = net_addr_pton(AF_INET, ipAddrStr, &ipAddr);
    printf("ip address to be set '%s' (converted to %i.%i.%i.%i, ret %i)\n",
            ipAddrStr,
            ipAddr.s4_addr[0], ipAddr.s4_addr[1],
            ipAddr.s4_addr[2], ipAddr.s4_addr[3],
            ret);
    struct net_if_addr *retAddr = net_if_ipv4_addr_add(iface, &ipAddr, NET_ADDR_MANUAL, 0);
    if (!retAddr)
    {
        printf("error when adding IPv4 address %i.%i.%i.%i\n",
               ipAddr.s4_addr[0], ipAddr.s4_addr[1],
               ipAddr.s4_addr[2], ipAddr.s4_addr[3]);
        return;
    }

    /* set IPv4 netmask */
    const char* netmaskStr = "255.255.0.0";
    struct in_addr netmask;
    ret = net_addr_pton(AF_INET, netmaskStr, &netmask);
    printf("netmask to be set '%s' (converted to %i.%i.%i.%i, ret %i)\n",
            netmaskStr,
            netmask.s4_addr[0], netmask.s4_addr[1],
            netmask.s4_addr[2], netmask.s4_addr[3],
            ret);
    net_if_ipv4_set_netmask(iface, &netmask);

    /* init network config */
    ret = net_config_init_app(NULL, "Initializing network");
    if (ret < 0)
    {
        printf("failed to initialize network settings for interface %s (err %i)\n",
               iface->if_dev->dev->name, ret);
    }
    else
    {
        printf("successfully initialized network settings for interface %s\n",
               iface->if_dev->dev->name);
    }
}

int main(void)
{
    int serv;
    struct sockaddr_in bind_addr;
    static int counter;

    /* print network config */
    struct net_if *iface = net_if_get_default();
    char buf[NET_IPV4_ADDR_LEN];
    printf("\nnetwork config before init:\n");
    printf("address: %s\n", net_addr_ntop(AF_INET, &iface->config.ip.ipv4->unicast[0].address.in_addr, buf, sizeof(buf)));
    printf("gateway: %s\n", net_addr_ntop(AF_INET, &iface->config.ip.ipv4->gw, buf, sizeof(buf)));
    printf("netmask: %s\n\n", net_addr_ntop(AF_INET, &iface->config.ip.ipv4->netmask, buf, sizeof(buf)));

    /* init network interface */
    custom_net_if_init();

    /* print network config */
    printf("\nnetwork config after init:\n");
    printf("address: %s\n", net_addr_ntop(AF_INET, &iface->config.ip.ipv4->unicast[0].address.in_addr, buf, sizeof(buf)));
    printf("gateway: %s\n", net_addr_ntop(AF_INET, &iface->config.ip.ipv4->gw, buf, sizeof(buf)));
    printf("netmask: %s\n\n", net_addr_ntop(AF_INET, &iface->config.ip.ipv4->netmask, buf, sizeof(buf)));

    serv = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (serv < 0)
    {
        printf("error: socket: %d\n", errno);
        exit(1);
    }

    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    bind_addr.sin_port = htons(BIND_PORT);

    if (bind(serv, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0)
    {
        printf("error: bind: %d\n", errno);
        exit(1);
    }

    if (listen(serv, 5) < 0)
    {
        printf("error: listen: %d\n", errno);
        exit(1);
    }

    printf("Single-threaded TCP echo server waits for a connection on "
           "port %d...\n",
           BIND_PORT);

    while (1)
    {
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        char addr_str[32];
        int client = accept(serv, (struct sockaddr *)&client_addr,
                            &client_addr_len);

        if (client < 0)
        {
            printf("error: accept: %d\n", errno);
            continue;
        }

        inet_ntop(client_addr.sin_family, &client_addr.sin_addr,
                  addr_str, sizeof(addr_str));
        printf("Connection #%d from %s\n", counter++, addr_str);

        while (1)
        {
            char buf[128], *p;
            int len = recv(client, buf, sizeof(buf), 0);
            int out_len;

            if (len <= 0)
            {
                if (len < 0)
                {
                    printf("error: recv: %d\n", errno);
                }
                break;
            }

            p = buf;
            do
            {
                out_len = send(client, p, len, 0);
                if (out_len < 0)
                {
                    printf("error: send: %d\n", errno);
                    goto error;
                }
                p += out_len;
                len -= out_len;
            } while (len);
        }

    error:
        close(client);
        printf("Connection from %s closed\n", addr_str);
    }
    return 0;
}
