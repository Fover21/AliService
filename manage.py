#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""
    此项目使用商户ID, 公私钥均为沙箱测试环境, 切勿商用
    如有疑问 +QQ: 404042726

"""

from urllib.parse import urlparse, parse_qs

from src.ali import (
    ali_pay,
    ali_certification,
    ali_transfer
)

import requests


if __name__ == '__main__':
    # TODO: 签名校验(所有接口的回调签名校验均为如此)
    return_url = 'http://47.92.87.172:8804/?total_amount=100.00&timestamp=2017-08-15+23%3A53%3A34&sign=e9E9UE0AxR84NK8TP1CicX6aZL8VQj68ylugWGHnM79zA7BKTIuxxkf%2FvhdDYz4XOLzNf9pTJxTDt8tTAAx%2FfUAJln4WAeZbacf1Gp4IzodcqU%2FsIc4z93xlfIZ7OLBoWW0kpKQ8AdOxrWBMXZck%2F1cffy4Ya2dWOYM6Pcdpd94CLNRPlH6kFsMCJCbhqvyJTflxdpVQ9kpH%2B%2Fhpqrqvm678vLwM%2B29LgqsLq0lojFWLe5ZGS1iFBdKiQI6wZiisBff%2BdAKT9Wcao3XeBUGigzUmVyEoVIcWJBH0Q8KTwz6IRC0S74FtfDWTafplUHlL%2Fnf6j%2FQd1y6Wcr2A5Kl6BQ%3D%3D&trade_no=2017081521001004340200204115&sign_type=RSA2&auth_app_id=2016080600180695&charset=utf-8&seller_id=2088102170208070&method=alipay.trade.page.pay.return&app_id=2016080600180695&out_trade_no=20170202185&version=1.0'
    o = urlparse(return_url)
    query = parse_qs(o.query)
    processed_query = {}
    ali_sign = query.pop("sign")[0]
    # print(ali_sign)
    for key, value in query.items():
        processed_query[key] = value[0]
    print(ali_pay.verify(processed_query, ali_sign))
    # ----------------------------------------------------------------

    # TODO: 生成支付的url
    pay_data = ali_pay.direct_pay(
        subject="luffycity",
        out_trade_no="20170212312312131355",
        total_amount=1,
        passback_params=str({'source': 'shop_cart', 'products': [1, 2, 3, 4]})
    )

    pay_url = ali_pay.generate_url(pay_data)
    print(pay_url)
    # ----------------------------------------------------------------

    # TODO: 生成转账的url
    trans_data = ali_transfer.transfer_pay("32423423423423459", "totdfv3788@sandbox.com", "10000")
    trans_url = ali_transfer.generate_url(trans_data)

    # TODO: 转账交易状态查询
    trans_response = {
        "alipay_fund_trans_toaccount_transfer_response":
            {
                "code": "10000",
                "msg": "Success",
                "order_id": "20171115110070001502270000026360",
                "out_biz_no": "32423423423423459",
                "pay_date": "2017-11-15 17:38:18"
            },
        "sign": "FD0Z4Shup82bfVXZfX+hlFiQHAyMAaHjUbZ6q4hMrUzdzqQ6LqjXdhhDwGIGZ1bKiTqzGjG2faghFqV6QbsWzj4iarX+/MeubcCeYhy78aSwar6w+zM1Mcwlkwmv0lkL7iLxQMvSBoltyV7lxmAjeJ5GoH5c0IoXJ+H5lGiAAbrPvrJ3CQnS+K7vuwhs+SOaO0Ed32Yj2KaTg63xyCmGh/MmKe96Eiu0LSmOzbgQTw31T3nsoxsiRw/90YCPrC4KRremFoj2FLs/7B96AsQI6+uDMiLh4I4tCHzrGFHPAMqWi4C/OGnjcNdHG48iUAIDOTFPd3ZuUrhHEePw3z/YzQ=="
    }

    trans_query_data = ali_transfer.transfer_query("32423423423423459", "20171115110070001502270000026360")
    trans_query_url = ali_transfer.generate_url(trans_query_data)
    # ----------------------------------------------------------------

    # TODO: 实名认证
    # 第一步: 认证初始化
    certification_data = ali_certification.authentication_initialize(
        "24312412131212",
        {
            "identity_type": "CERT_INFO",
            "cert_type": "IDENTITY_CARD",
            "cert_name": "沙箱环境",
            "cert_no": "489622198711040012"
        }
    )

    certification_url = ali_certification.generate_url(certification_data)
    cert_response = requests.get(certification_url).json()
    """
    e.g 成功示例
    response = {
        "zhima_customer_certification_initialize_response": {
            "code": "10000",
            "biz_no": "7ae06125ac5fe30a433aa5671fe80651",
            "msg": "Success"
        },
        "sign": "Po6RRMnmnUeTNHiY233I2gE1ipU++nsULmyhYiJMwTkYh+w76UtgOw78L2tAqB/G1WBG7KyPOFoxtYD4f9Zksx7vxKv7H9iXlY2RV6IZMzELzGBNMJECoju6sB/M7sHPBjqATc9KX7qBtdKDJChp6C22zShzdsWzIYrdedDHzBFJeLh4U4Am7QXnUCEwKjbhBx0ASnDHa/oNsznjH1Nhmfl8aTCEwsPYvRL0C0sqHkxUz0c5Lz72M3Zz5qlaPdBunEJx2SVUJcwF+6YY0H+LkPo31ZJKjSUxcD71cl8X2fO5K69+g3f7z3RTfDQ8w1CCrG0nLkRa71K3OrziL/qhzA=="
    }
    """
    # 根据请求返回值获取 biz_no (本次认证的唯一标识，商户需要记录，后续的操作都需要用到)
    # 第二步: 开始认证
    start_cert_data = ali_certification.certify(
        "7ae06125ac5fe30a433aa5671fe80651", return_url="http://公网ip/cert/callback/",

    )
    start_cert_url = ali_certification.generate_url(start_cert_data)
    # 此url在手机端中打开, 如果认证成功即会向 return_url 进行回调
    """
    e.g 响应示例
    {
        "zhima_customer_certification_certify_response": {
            "code": "10000",
            "msg": "Success",
            "biz_no": "ZM201612013000000393900404029253",
            "passed": "true",
            "failed_reason": "认证成功"
        },
        "sign": "ERITJKEIJKJHKKKKKKKHJEREEEEEEEEEEE"
    }
    """
    # 第三步: 认证查询
    cert_query_data = ali_certification.query("ZM201612013000000393900404029253")
    cert_query_url = ali_certification.generate_url(cert_query_data)
    # 请求并获取查询结果
