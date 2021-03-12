import datetime, time

tag_list = ["Architecture", "Environments", "Input and Error Handling", "Database", "DR & BC",
            "Version Management & Updates", "Logging & Monitoring", "Password Policy", "Encryption", "Sensitive Data",
            "Documentation & Legal Agreements", "Hardening", "Security Systems", "Configuration",
            "Users Permissions & Authentication", "Firewall", "Remote Access", "Policies & Procedures",
            "Development", "PT", "Infrastructure", "Mobile", "Web", "Client", "Reconnaissance", "Phishing",
            "Supply Chain", "Communication & Protocols", "Hijack", "Remote Code Execution", "Persistence",
            "Privilege Escalation", "Evasion", "Credentials", "Lateral Movement", "File Upload", "Token",
            "Obfuscation", "Denial of Service", "Injection", "XSS", "Virtualization", "Cloud", "Encoding",
            "Man In The Middle", "Local File Inclusion", "Remote File Inclusion"]


public_key = '''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5C87tihlDKkjp6H55/lp
cCClrE7zHRLeNAbO1wELIkZzsw2EYzySjTHp594cadOupNqt57SnNoHyaPYPC4Ap
IyuWxUmYAak1FisZDpM/V108+/ZYIuFqPE6RfP//w05wanihyVCxT6RizW0hilxk
kf+hTUOvgvpGm5HW3PKnMECypd2ve+A7ogcUTN6Cd6EXzPmBVSxp1OrgadRo+1eA
6rXFGQKL13acU2KhViOtx1J8GSoow9Cz30gqqg9MY/CliZexlcGku191CH11H0nC
BHc2pYz3tnen5SJukZkUGZZcwRcMhe/T1wymU4d6DKFc1/CJOZrhY/1Xyj7Mxo5v
VQIDAQAB
-----END PUBLIC KEY-----
'''

private_key = '''5C87tihlDKkjp6H55_lpcCClrE7zHRLeNAbO1wELIkZzsw2
EYzySjTHp594cadOupNqt57SnNoHyaPYPC4ApIyuWxUmYAak1FisZDpM_V108-_Z
YIuFqPE6RfP__w05wanihyVCxT6RizW0hilxkkf-hTUOvgvpGm5HW3PKnMECypd2
ve-A7ogcUTN6Cd6EXzPmBVSxp1OrgadRo-1eA6rXFGQKL13acU2KhViOtx1J8GSo
ow9Cz30gqqg9MY_CliZexlcGku191CH11H0nCBHc2pYz3tnen5SJukZkUGZZcwRc
Mhe_T1wymU4d6DKFc1_CJOZrhY_1Xyj7Mxo5vVQ'''


def search_results(keywords, tags_list, item):
    title = item['Title']
    title_strip = title.strip().split(' ')
    body = item['Description']
    body_strip = body.strip().split(' ')
    details = item['RiskDetails']
    details_strip = details.strip().split(' ')
    tags = item['Tags']

    if any(i in tags_list for i in tags):
        return True
    elif any(i in keywords for i in title_strip) or any(i in keywords for i in body_strip) or any(i in keywords for i in details_strip):
        return True


def get_user_data_from_cookies(user_request):
    data = {"uid": user_request.cookies.get('uid'),
            "username": user_request.cookies.get('username'),
            "email": user_request.cookies.get('email'),
            "admin": user_request.cookies.get("admin"),
            "editor": user_request.cookies.get("editor")
            }
    return data


def get_real_datetime_from_timestamp(timestamp):
    real_time = str(datetime.datetime.fromtimestamp(float(timestamp) // 1000.0).strftime("%d-%m-%Y %H:%M:%S"))
    return real_time


def get_real_date_from_timestamp(timestamp):
    real_time = str(datetime.datetime.fromtimestamp(float(timestamp) // 1000.0).strftime("%d-%m-%Y"))
    return real_time


def get_current_timestamp():
    return str(round(time.time() * 1000))

