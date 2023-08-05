from tls_client   import Session
from threading    import Thread
from colorama     import Fore
from os           import system, _exit
from time         import sleep
from json         import loads, dumps
from base64       import b64encode
from httpx        import get, delete, post
from random       import choice, randint
from terminut     import Console
from toml         import load
import time
import sys
import os
import subprocess 
import logging 
import requests 
import httpx 
local_veilcord_path = os.path.abspath("veilcord")
sys.path.insert(0, local_veilcord_path)
import veilcord.__main__ as veilcord
from veilcord     import VeilCord, extractCode

config = load("config.toml").get("opts")
logging.basicConfig(level=logging.ERROR, filename="error_log.txt", filemode="a", format="%(asctime)s - %(levelname)s - %(message)s") 
Console.init(colMain=Fore.MAGENTA)

def get_hwid():
    p = subprocess.Popen('wmic csproduct get uuid', stdout=subprocess.PIPE)
    out, _ = p.communicate()
    hwid = out.decode().split('\n')[1].strip()
    return hwid

def authenticate():
    hwid = get_hwid()
    json_data = {'hwid' : hwid}
    return_response = requests.post("https://zeetechorg.000webhostapp.com/twez/verify_hwid.php", json=json_data)
    response_content = return_response.text
    if (response_content == 'false'):
        print(f"\033[92m\n\t(-) License not Activated\033[0m")
        exit(1)


class Rotater:
    def __init__(self):
        self.proxies = [line.strip() for line in open("proxies.txt", "r")]
        self.proxy = choice(self.proxies)

    def rotate_proxy(self):
        while True:
            interval = int(config.get('proxy_rotate_time'))
            time.sleep(interval)
            self.proxy = choice(self.proxies)

    @staticmethod
    def get_proxy():
        return Rotater().proxy

rotater = Rotater()
Thread(target=rotater.rotate_proxy).start()


class Captcha:
    def __init__(self) -> None:
        # self.proxies = [line.strip() for line in open("proxies.txt", "r")]
        # self.proxy = choice(self.proxies)
        self.proxy = Rotater.get_proxy()
        self.key, self.url = (config.get("capsolver_api_key"), "ignore")
        if not self.key:
            print(f"\033[91m\n\t(-) No API Key Specified in Configuration File\033[0m")
            

    def solveCaptcha(
        self,
        site_key: str = "b2b02ab5-7dae-4d6f-830e-7b55634c888b",
        # site_key: str = "4c672d35-0701-42b2-88c3-78380b0db560",
        site_url: str = "https://discord.com",
        domain: str = "https://api.capsolver.com",
        rqdata: str = None
    ) -> str:
        taskType = "HCaptchaTurboTask" 
        data1 = {
            "clientKey": self.key,
            "appId": "5C4B67D5-D8E9-485D-AF57-4F427464F0CF",
            # "appId": "E68E89B1-C5EB-49FE-A57B-FBE32E34A2B4",
            "task": {
                "type": taskType,
                "websiteURL": site_url,
                "websiteKey": site_key,
                # "userAgent": 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36',
                "isInvisible": True,
                "enterprisePayload": {
                    "rqdata": rqdata
                },
                "proxy" : self.proxy,
            }

        }
        try:
            resp1 = post(f"{domain}/createTask", json=data1)
            if resp1.json().get("errorId") == 0:
                taskId = resp1.json().get("taskId")
                data = {
                    "clientKey": self.key,
                    "taskId": taskId
                }
                resp = post(f"{domain}/getTaskResult", json=data)
                status = resp.json().get("status")
                while status == "processing":
                    print(f"\033[91mAPI Says Status = {status}\033[0m")
                    sleep(1)
                    resp = post(f"{domain}/getTaskResult", json=data)
                    status = resp.json().get("status")

                if status == "ready":
                    print(f"\033[92mAPI Says Status = {status}\033[0m")
                    captchaToken = resp.json().get("solution").get("gRecaptchaResponse")
                    print(f"\033[92mAPI gave captcha Token {captchaToken[:40]}\033[0m")
                    return captchaToken
                else:
                    return self.solveCaptcha()
            else:
                print(f"API RESPONSE => {resp1.json()}")
                return "fail"
        except Exception as e:
            logging.error(f"Captcha solving error: {e}")
            print(f"Captcha solving error: {e}")
            return "fail"


class Joiner:
    def __init__(self, invite, proxies = None, xcontext = None) -> None: 
        self.invite = invite
        self.xcontext = xcontext
        self.proxies = proxies

    def newSession(self):
        proxies_dict = {}

        if self.proxies:
            # proxy = choice(self.proxies)
            proxy = Rotater.get_proxy()
            proxies_dict = {"http": proxy, "https": proxy}
        else:
            proxies_dict = None

        self.client = Session(
            # client_identifier="discord_1_0_9013",
            client_identifier="discord_1_0_9015",
            random_tls_extension_order=True,
        )
        self.client.proxies = proxies_dict
        self.veilcord = VeilCord(self.client, "app")
        xsup = self.veilcord.generateXProp()
        # self.client.proxies.update(proxies_dict)
        self.client.headers = {
            "authority": "discord.com",
            "accept": "*/*",
            "accept-language": "en-US",
            "connection": "keep-alive",
            "content-type": "application/json",
            "origin": "https://discord.com",
            "referer": "https://discord.com/channels/@me",
            'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            # "user-agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.9015 Chrome/108.0.5359.215 Electron/22.3.12 Safari/537.36",
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36',
            "x-debug-options": "bugReporterEnabled",
            "x-discord-locale": "en-US",
            "x-discord-timezone": "America/New_York",
            "x-super-properties": xsup,
            # "x-super-properties": "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiRGlzY29yZCBDbGllbnQiLCJyZWxlYXNlX2NoYW5uZWwiOiJzdGFibGUiLCJjbGllbnRfdmVyc2lvbiI6IjEuMC45MDEzIiwib3NfdmVyc2lvbiI6IjEwLjAuMjI2MjEiLCJvc19hcmNoIjoieDY0Iiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV09XNjQpIEFwcGxlV2ViS2l0LzUzNy4zNiAoS0hUTUwsIGxpa2UgR2Vja28pIGRpc2NvcmQvMS4wLjkwMTMgQ2hyb21lLzEwOC4wLjUzNTkuMjE1IEVsZWN0cm9uLzIyLjMuMiBTYWZhcmkvNTM3LjM2IiwiYnJvd3Nlcl92ZXJzaW9uIjoiMjIuMy4yIiwiY2xpZW50X2J1aWxkX251bWJlciI6MTk5NTM3LCJuYXRpdmVfYnVpbGRfbnVtYmVyIjozMjI2NiwiY2xpZW50X2V2ZW50X3NvdXJjZSI6bnVsbCwiZGVzaWduX2lkIjowfQ==",

        }
        if self.xcontext is not None:
            self.client.headers["x-context-properties"] = self.xcontext
            
        
        self.veilcord = VeilCord(self.client, "app")
        cookies = self.veilcord.getFingerprint()
        # cookies = self.veilcord.getFingerprint(self.client.headers.get("x-super-properties"),cookieType="json")
        # cookies = self.veilcord.getFingerprint(xsup,cookieType="json")
        self.client.cookies = cookies[1]
        self.fingerp = cookies[0]
        
        return self.client

    def getUser(self, token):
        headers = {"Authorization": f"{token}"}
        response = self.client.get(
            "https://discord.com/api/v9/users/@me", headers=headers
            ,proxy=Rotater.get_proxy()
        )

        if response.status_code == 200:
            data = response.json()
            self.user_id = data["id"]
        else:
            Console.printf(f"(!) Error fetching self ID: {response.status_code}")


    def join(self, token, invite, bypass, hideJoin, captcha=None, caprq=None):
        if captcha == "fail": return
        self.newSession()
        if config.get("ShowWS"):
            Console.printf(f"(~) Connecting Token To Websocket [{token[:40]}...]")
        session = self.veilcord.openSession()
        session_id = self.veilcord.getSession(session, token, keep_alive =True, show_hb = True)
        # session_id = self.veilcord.getSession(token=token)
        
        if session_id is None:
            return print("(!) Failed Getting SessionID.")
        
        try:
            self.client.headers["authorization"] = token
            self.client.headers = {
            "accept": "*/*",
            "accept-language": "en-US",
            'accept-encoding': 'application/json',
            'content-type': 'application/json',
            "authorization": token,
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.9013 Chrome/108.0.5359.215 Electron/22.3.2 Safari/537.36",
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
            'sec-gpc': '1',
            "x-discord-locale": "en-US",
            "origin": "https://discord.com",
            "referer": "https://discord.com/channels/@me",
            "mode": "cors",
            # 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0',
            # 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36',
            # 'Accept': '*/*',
            # 'Accept-Language': 'fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3',
            # 'Accept-Encoding': 'gzip, deflate, br',
            # 'Content-Type': 'application/json',
            # 'X-Context-Properties': 'eyJsb2NhdGlvbiI6IkpvaW4gR3VpbGQiLCJsb2NhdGlvbl9ndWlsZF9pZCI6Ijk4OTkxOTY0NTY4MTE4ODk1NCIsImxvY2F0aW9uX2NoYW5uZWxfaWQiOiI5OTAzMTc0ODgxNzg4NjgyMjQiLCJsb2NhdGlvbl9jaGFubmVsX3R5cGUiOjB9',
            # 'Authorization': token,
            'X-Super-Properties': 'eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiRmlyZWZveCIsImRldmljZSI6IiIsInN5c3RlbV9sb2NhbGUiOiJmciIsImJyb3dzZXJfdXNlcl9hZ2VudCI6Ik1vemlsbGEvNS4wIChXaW5kb3dzIE5UIDEwLjA7IFdpbjY0OyB4NjQ7IHJ2OjEwMi4wKSBHZWNrby8yMDEwMDEwMSBGaXJlZm94LzEwMi4wIiwiYnJvd3Nlcl92ZXJzaW9uIjoiMTAyLjAiLCJvc192ZXJzaW9uIjoiMTAiLCJyZWZlcnJlciI6IiIsInJlZmVycmluZ19kb21haW4iOiIiLCJyZWZlcnJlcl9jdXJyZW50IjoiIiwicmVmZXJyaW5nX2RvbWFpbl9jdXJyZW50IjoiIiwicmVsZWFzZV9jaGFubmVsIjoic3RhYmxlIiwiY2xpZW50X2J1aWxkX251bWJlciI6MTM2MjQwLCJjbGllbnRfZXZlbnRfc291cmNlIjpudWxsfQ==',
            # 'X-Discord-Locale': 'en-US',
            # 'X-Debug-Options': 'bugReporterEnabled',
            # 'Origin': 'https://discord.com',
            # 'DNT': '1',
            # 'Connection': 'keep-alive',
            # 'Referer': 'https://discord.com',
            # 'Cookie': '__dcfduid=21183630021f11edb7e89582009dfd5e; __sdcfduid=21183631021f11edb7e89582009dfd5ee4936758ec8c8a248427f80a1732a58e4e71502891b76ca0584dc6fafa653638; locale=en-US',
            # 'Sec-Fetch-Dest': 'empty',
            # 'Sec-Fetch-Mode': 'cors',
            # 'Sec-Fetch-Site': 'same-origin',
            # 'TE': 'trailers',
        }

            if captcha is not None:
                self.client.headers["x-captcha-key"] = captcha
                self.client.headers["x-captcha-rqtoken"] = caprq

            payload = {"session_id": session_id,'consent': True,'captcha_key': captcha,'captcha_rqtoken':caprq,'fingerprint': self.fingerp,"invite": invite}
            self.client.headers["content-length"] = str(len(dumps(payload)))
            
            r = self.client.post(
                f"https://discord.com/api/v9/invites/{invite}",
                json=payload,
                proxy = Rotater.get_proxy(),
                headers=self.client.headers,
                
            )
            
            if r.status_code == 200:
                print(f"\033[92m\n\t(+) joined [{invite}] - [200] \n\033[0m")
                if bypass:
                    self.bypassRules(token, invite, r.json()["guild"]["id"])
                if hideJoin:
                    self.DeleteJoinMessage(token, r.json()["guild"]["id"])
            elif r.status_code == 429:
                Console.printf(f"(-) RATELIMIT BY CLOUDFLARE | use proxies or vpn")
                return sleep(3)
            elif r.status_code == 403:
                if "captcha" in r.text:
                    return Console.printf("(!) Invalid CaptchaKey")
                if "The user is banned from this guild." in r.text:
                    return Console.printf("(!) Token banned from server.")
                if config.get("RemoveLocked"):
                    with open("tokens.txt", 'r+') as file:
                        file.seek(0)
                        file.writelines([line for line in file.readlines() if token not in line])
                        file.truncate()
                return Console.printf(f"(-) Token Locked. [{token[:40]}]")
            elif r.status_code == 401:
                if config.get("RemoveInvalid"):
                    with open("tokens.txt", 'r+') as file:
                        file.seek(0)
                        file.writelines([line for line in file.readlines() if token not in line])
                        file.truncate()
                return Console.printf(f"(-) Token Invalid. [{token[:40]}]")
            elif r.status_code == 400:
                Console.printf(f"(-) Captcha detected [{token[:40]}]")
                logging.error(r.text)
                rqtoken = r.json().get("captcha_rqtoken")
                rqdata = r.json().get("captcha_rqdata")
                key = Captcha().solveCaptcha(rqdata=rqdata)
                while True:
                    if key is not None:
                        print(f"\033[92mRetrying Again with key = {key[:40]}\033[0m")
                        return self.join(token, invite, bypass, hideJoin, captcha=key, caprq=rqtoken)
                    else:
                        print("\nWaiting for captcha to be solved...\n")
                        sleep(5)
            else:
                return Console.printf(f"(!) Error => [{r.text}]")
        except Exception as e:
            Console.printf(f"(!) Join Exception: {e}")
            return self.join(token, invite, bypass, hideJoin)

    def bypassRules(self, token, invcode, guildid):
        try:
            self.client.headers["authorization"] = token
            self.client.headers = {
            "accept": "*/*",
            "accept-language": "en-US",
            'accept-encoding': 'application/json',
            'content-type': 'application/json',
            "authorization": token,
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.9013 Chrome/108.0.5359.215 Electron/22.3.2 Safari/537.36",
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
            'sec-gpc': '1',
            "x-discord-locale": "en-US",
            "origin": "https://discord.com",
            "referer": "https://discord.com/channels/@me",
            "mode": "cors",
            'X-Super-Properties': 'eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiRmlyZWZveCIsImRldmljZSI6IiIsInN5c3RlbV9sb2NhbGUiOiJmciIsImJyb3dzZXJfdXNlcl9hZ2VudCI6Ik1vemlsbGEvNS4wIChXaW5kb3dzIE5UIDEwLjA7IFdpbjY0OyB4NjQ7IHJ2OjEwMi4wKSBHZWNrby8yMDEwMDEwMSBGaXJlZm94LzEwMi4wIiwiYnJvd3Nlcl92ZXJzaW9uIjoiMTAyLjAiLCJvc192ZXJzaW9uIjoiMTAiLCJyZWZlcnJlciI6IiIsInJlZmVycmluZ19kb21haW4iOiIiLCJyZWZlcnJlcl9jdXJyZW50IjoiIiwicmVmZXJyaW5nX2RvbWFpbl9jdXJyZW50IjoiIiwicmVsZWFzZV9jaGFubmVsIjoic3RhYmxlIiwiY2xpZW50X2J1aWxkX251bWJlciI6MTM2MjQwLCJjbGllbnRfZXZlbnRfc291cmNlIjpudWxsfQ==',
        }

            rulereq = get(
                f"https://discord.com/api/v9/guilds/{guildid}/member-verification?with_guild=false&invite_code={invcode}",
                headers=self.client.headers,
            )
            # print(f"Rule Req = {rulereq}")
            if rulereq.status_code != 200:
                return print(
                    f"{rulereq.status_code} | Failed to bypass rules cuz idk | Response from Discord : {rulereq.text}"
                )
            submitpayload = rulereq.json()
            submitpayload["form_fields"][0]["response"] = True
            del submitpayload["description"]
            submitpayload = dumps(submitpayload)
            self.client.headers["content-length"] = str(len(submitpayload))
            self.client.headers["content-type"] = "application/json"
            res = self.client.put(
                f"https://discord.com/api/v9/guilds/{guildid}/requests/@me",
                data=submitpayload,
                headers=self.client.headers
            )
            print(f"\033[92mBypassRules Request Response => {res.status_code}\033[0m")
        except Exception as e:
            Console.printf(f"(!) err@bypassRules: {e}")

    def DeleteJoinMessage(self, token, guildid):
        self.client.headers["authorization"] = token
        self.getUser(token)
        res = self.client.get(f"https://discord.com/api/v9/guilds/{guildid}")
        if "system_channel_id" in res.text:
            chanid = res.json()["system_channel_id"]
            try:
                response = get(
                    f"https://discord.com/api/v9/channels/{chanid}/messages",
                    params={"limit": "5"}
                )
                if response.json()[0]["type"] == 7:
                    if int(response.json()[0]["author"]["id"]) == int(self.user_id):
                        try:
                            fRes = delete(
                                f'https://discord.com/api/v9/channels/{chanid}/messages/{response.json()[0]["id"]}',
                            )
                            if fRes.is_success:
                                Console.printf(f"(+) Deleted Join Message.")
                            else:
                                Console.printf(f"(!) join message del status @ {fRes}")
                        except:
                            Console.printf("(!) failed del join message")
            except Exception as e:
                Console.printf(f"(!) Failed to delete join message. {e}")


def start():
    system("cls")
    Console.printf(
        f"""
     /$$$$$           /$$                                     /$$                       /$$$$$$$$                 /$$
   |__  $$          |__/                                    | $$                      |_____ $$                 | $$
      | $$  /$$$$$$  /$$ /$$$$$$$   /$$$$$$   /$$$$$$       | $$$$$$$  /$$   /$$           /$$/   /$$$$$$   /$$$$$$$
      | $$ /$$__  $$| $$| $$__  $$ /$$__  $$ /$$__  $$      | $$__  $$| $$  | $$          /$$/   /$$__  $$ /$$__  $$
 /$$  | $$| $$  \ $$| $$| $$  \ $$| $$$$$$$$| $$  \__/      | $$  \ $$| $$  | $$         /$$/   | $$  \ $$| $$  | $$
| $$  | $$| $$  | $$| $$| $$  | $$| $$_____/| $$            | $$  | $$| $$  | $$        /$$/    | $$  | $$| $$  | $$
|  $$$$$$/|  $$$$$$/| $$| $$  | $$|  $$$$$$$| $$            | $$$$$$$/|  $$$$$$$       /$$$$$$$$|  $$$$$$/|  $$$$$$$
 \______/  \______/ |__/|__/  |__/ \_______/|__/            |_______/  \____  $$      |________/ \______/  \_______/
                                                                       /$$  | $$                                    
                                                                      |  $$$$$$/                                    
                                                                       \______/                                     
YTB => https://youtube.com/@GeneralZodX698
IG => https://www.instagram.com/general_zodx
                                                                                                  
Follow the instructions on screen to continue.
Session initialized...

    """
        + Fore.RESET,
        showTimestamp=False,
    )

    with open("tokens.txt", "r") as f:
        tokens = [x.strip() for x in f.readlines()]

    proxies = [line.strip() for line in open("proxies.txt", "r")]

    if len(tokens) > 100 and not proxies:
        print("Use proxies")


    link = Console.inputf("(?) Invite > ")
    inv = extractCode(link)
    if inv is None:
        Console.printf("(!) Invite check failed.", showTimestamp=False)
        return
    res = get(f"https://discord.com/api/v9/invites/{inv}")
    if res.status_code == 404:
        return Console.printf("(!) Invalid Invite.", showTimestamp=False)

    WAIT_AMT = Console.inputf("(?) Join Delay > ")
    WAIT_AMT = int(WAIT_AMT) if WAIT_AMT else 2
    bypass = Console.inputf("(?) Bypass Rules (y/N) > ").lower() == "y"
    deljoin = Console.inputf("(?) Delete Join Message (y/N) > ").lower() == "y"

    try:
        res = get(
            f"https://discord.com/api/v9/invites/{inv}?inputValue={inv}&with_counts=true&with_expiration=true"
        ).json()
        jsonContext = {
            "location": "Join Guild",
            "location_guild_id": str(res["guild"]["id"]),
            "location_channel_id": str(res["channel"]["id"]),
            "location_channel_type": int(res["channel"]["type"]),
        }
        json_str = dumps(jsonContext)
        xContext = b64encode(json_str.encode()).decode()
        xcontext = xContext
    except:
        xcontext = None
    # print()
    dis = Joiner(inv, proxies, xcontext)
    for token in tokens:
        Thread(target=dis.join, args=[token, inv, bypass, deljoin]).start()
        sleep(WAIT_AMT)




if __name__ == "__main__":
    try:
        authenticate()
        start()
    except KeyboardInterrupt:
        _exit(0)
    except Exception as e:
        Console.printf(f"(!) Thread Exception: {e}")
