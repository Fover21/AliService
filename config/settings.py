#! /usr/bin/env python
# -*- coding: utf-8 -*-


"""
    阿里支付宝相关配置
"""

import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class AliConfig:

    # 商户app_id
    app_id = "2016081500252288"

    # 商户私钥路径
    merchant_private_key_path = os.path.join(BASE_DIR, "keys", "app_private_2048.txt")

    # 支付宝公钥路径
    ali_public_key_path = os.path.join(BASE_DIR, "keys", "ali_public_2048.txt")

    # 服务器异步通知页面路径 需http: // 格式的完整路径，不能加?id = 123 这类自定义参数，必须外网可以正常访问
    # 发post请求
    pay_notify_url = "http://47.94.172.250:8804/api/v1/trade/alipay/"

    # 页面跳转同步通知页面路径 需http: // 格式的完整路径，不能加?id = 123 这类自定义参数，必须外网可以正常访问
    # 发get请求
    pay_return_url = "http://47.94.172.250:8804/api/v1/trade/alipay/"

    # 签名方式(当前只支持RSA和RSA2)
    sign_type = "RSA2"

    # 字符编码格式
    charset = "utf-8"

    # 是否启动调试模式
    debug = True


