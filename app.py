"""
微信公众号消息回调服务 —— 羊肉生鲜预定
================================================
功能：
1. GET  /wechat   微信服务器签名校验（在公众号后台配置 URL 时，微信会先发这个请求）
2. POST /wechat   接收用户发来的消息，按关键词返回文本回复
3. GET  /          健康检查接口（Render 等平台探活 / 部署后自测用）

运行方式：
- 本地调试：python app.py
- 线上部署：gunicorn app:app

依赖文件：requirements.txt / 配置文件：.env
"""

import hashlib
import logging
import os
import time
from xml.etree import ElementTree as ET

from dotenv import load_dotenv
from flask import Flask, make_response, request

# 读取 .env 里的配置（本地开发用；Render 等平台一般在后台环境变量里配置）
load_dotenv()

# 公众号后台「设置与开发 - 基本配置 - 服务器配置」里自己填写的 Token，必须和这里保持一致
WECHAT_TOKEN = os.getenv("WECHAT_TOKEN", "change_me_token")

# 本地调试端口（Render 会注入自己的 PORT 环境变量，这里自动适配）
PORT = int(os.getenv("PORT", "5000"))

app = Flask(__name__)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


# ==========================================================
# 一、可配置区：关键词 -> 回复内容（想改话术、改价格只动这里）
# ==========================================================
KEYWORD_REPLIES = {
    "预定": "🐑每周现杀羊肉预定，羊腿、羊排、全羊，预定进群接龙。\n"
            "附预定规则：提前1天下单，支持自提/同城配送，带检疫证明。\n"
            "⏰ 本周预定周四晚截止，周六上午取货。",
    "价格": "羊腿38元/斤，羊排40元/斤，羊蝎子45元/斤，礼盒另算，配送费按距离收取。",
    "配送": "【配送范围】市区三环内及周边10公里，超出范围可协商自提。\n"
            "【配送时间】每日9:00-18:00，当天17点前下单，次日上午送达。\n"
            "【自提地址】XX市XX区XX路88号 农贸市场B区12号档口。",
}

# 没命中任何关键词时的兜底回复
DEFAULT_REPLY = "您好，回复【预定】查看预定方式，回复【价格】查看报价。"


# ==========================================================
# 二、微信签名校验
# ==========================================================
def check_signature(signature: str, timestamp: str, nonce: str) -> bool:
    """
    按微信官方规则校验签名：
    把 token、timestamp、nonce 三个值按字典序排序，拼成一个字符串，
    做 sha1 加密得到十六进制字符串，再和微信传来的 signature 对比。
    """
    if not (signature and timestamp and nonce):
        return False

    raw = "".join(sorted([WECHAT_TOKEN, timestamp, nonce]))
    calc = hashlib.sha1(raw.encode("utf-8")).hexdigest()

    # 用密文比较，避免被时序攻击（本地小服务无所谓，写规范点没坏处）
    return hmac_compare(calc, signature)


def hmac_compare(a: str, b: str) -> bool:
    """长度一致时逐字符比较，等价于常量时间比较的简化写法"""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    return result == 0


# ==========================================================
# 三、XML 解析与文本回复构造
# ==========================================================
def parse_message(xml_bytes: bytes) -> dict:
    """
    把微信推过来的 XML 消息体解析成 Python 字典。
    例如：<xml><FromUserName>abc</FromUserName>...</xml> -> {"FromUserName": "abc", ...}
    解析失败返回空字典，由调用方兜底。
    """
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        logger.warning("XML 解析失败：%s", exc)
        return {}
    # 微信消息只有一层子节点，直接取 tag -> text
    return {child.tag: (child.text or "") for child in root}


def build_text_reply(to_user: str, from_user: str, content: str) -> str:
    """
    构造「文本消息」回复 XML。
    注意：微信要求回复时收发双方互换 —— 用户发来的 FromUserName 变成回复的 ToUserName。
    """
    return (
        "<xml>"
        f"<ToUserName><![CDATA[{to_user}]]></ToUserName>"
        f"<FromUserName><![CDATA[{from_user}]]></FromUserName>"
        f"<CreateTime>{int(time.time())}</CreateTime>"
        "<MsgType><![CDATA[text]]></MsgType>"
        f"<Content><![CDATA[{content}]]></Content>"
        "</xml>"
    )


def get_reply(content: str) -> str:
    """
    关键词匹配：命中就返回对应话术，都没命中返回兜底回复。
    先去掉首尾空白和空格，防止用户手滑打出「预 定」匹配不上。
    """
    text = content.strip().replace(" ", "")

    for keyword, reply in KEYWORD_REPLIES.items():
        if keyword in text:
            return reply

    return DEFAULT_REPLY


# ==========================================================
# 四、路由
# ==========================================================
@app.route("/", methods=["GET"])
def health():
    """健康检查：部署完可以浏览器打开看看服务活没活"""
    return "mutton wechat service is running"


@app.route("/wechat", methods=["GET"])
def wechat_verify():
    """
    微信服务器配置校验（GET）。
    校验通过后必须【原样返回 echostr】，微信才会提示「配置成功」。
    """
    signature = request.args.get("signature", "")
    timestamp = request.args.get("timestamp", "")
    nonce = request.args.get("nonce", "")
    echostr = request.args.get("echostr", "")

    if check_signature(signature, timestamp, nonce):
        logger.info("签名校验通过，返回 echostr")
        return echostr

    logger.warning("签名校验失败 signature=%s timestamp=%s nonce=%s", signature, timestamp, nonce)
    return "signature check failed", 403


@app.route("/wechat", methods=["POST"])
def wechat_message():
    """
    接收用户消息（POST），按关键词返回文本回复。
    微信要求 5 秒内响应，否则会重试；这里都是纯内存处理，速度足够。
    """
    # 4.1 同样先校验签名，防止接口被陌生人伪造请求刷着玩
    signature = request.args.get("signature", "")
    timestamp = request.args.get("timestamp", "")
    nonce = request.args.get("nonce", "")
    if not check_signature(signature, timestamp, nonce):
        logger.warning("POST 签名校验失败，拒绝处理")
        return "signature check failed", 403

    # 4.2 解析微信推来的 XML
    msg = parse_message(request.data)
    if not msg:
        return "success"

    msg_type = msg.get("MsgType", "")

    # 4.3 只处理文本消息。图片/语音/事件（关注、取关等）一律不回复，
    #     直接返回字符串 "success"，微信收到后不会给用户推任何内容。
    if msg_type != "text":
        logger.info("收到非文本消息 MsgType=%s，不作回复", msg_type)
        return "success"

    content = msg.get("Content", "")
    # 回复时收发双方互换：用户 -> 公众号 变成 公众号 -> 用户
    to_user = msg.get("FromUserName", "")
    from_user = msg.get("ToUserName", "")

    reply_content = get_reply(content)
    logger.info("收到内容=%s | 回复=%s", content, reply_content.replace("\n", " "))

    reply_xml = build_text_reply(to_user, from_user, reply_content)
    # 响应体为 XML，且必须是纯 XML 字符串，不要带多余换行
    return make_response(reply_xml, 200, {"Content-Type": "application/xml"})


if __name__ == "__main__":
    # 仅本地调试使用；线上请用 gunicorn app:app 启动
    app.run(host="0.0.0.0", port=PORT, debug=True)
