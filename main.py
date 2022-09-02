import requests
from lxml import html
import json
import datetime
import jwt
from Crypto import Random
from Crypto.Cipher import AES
import base64
import numpy as np
from hashlib import md5
import discord



#Config
global AgentName 
AgentName = 'agentName'
global Password 
Password = 'agentPassword'



##################
BLOCK_SIZE = 16
headers = {'Content-Type': 'application/json'
}


#ENCRYPTIOn AES
def pad(data):
    length = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + (chr(length)*length).encode()

def unpad(data):
    return data[:-(data[-1] if type(data[-1]) == int else ord(data[-1]))]

def bytes_to_key(data, salt, output=48):
    assert len(salt) == 8, len(salt)
    data += salt
    key = md5(data).digest()
    final_key = key
    while len(final_key) < output:
        key = md5(key + data).digest()
        final_key += key
    return final_key[:output]

def encrypt(message, passphrase):
    salt = Random.new().read(8)
    key_iv = bytes_to_key(passphrase, salt, 32+16)
    key = key_iv[:32]
    iv = key_iv[32:]
    aes = AES.new(key, AES.MODE_CBC, iv)
    return base64.b64encode(b"Salted__" + salt + aes.encrypt(pad(message)))

def decrypt(encrypted, passphrase):
    encrypted = base64.b64decode(encrypted)
    assert encrypted[0:8] == b"Salted__"
    salt = encrypted[8:16]
    key_iv = bytes_to_key(passphrase, salt, 32+16)
    key = key_iv[:32]
    iv = key_iv[32:]
    aes = AES.new(key, AES.MODE_CBC, iv)
    return unpad(aes.decrypt(encrypted[16:]))
#ENCRYPTION AES END



#with requests.Session() as s:

def login():
    s = requests.Session()
    login_url = "http://ggpoker.ggcore.net/auth/agent"
    login_data = {'AgentName':AgentName,'Password':Password}  
    s.put(login_url, json=login_data, headers=headers)
    return s

def get_player_id(s, mail):
    player_data = {"AgentName": AgentName,"PageSize": "20"}
    player_data_url = "http://ggpoker.ggcore.net/api/get/GetPlayersRequest"
    r=''
    player_id = ''
    r=s.post(player_data_url, json=player_data)
    players = json.loads(r.text)['List']
    for player in players:
        if mail in player["Email"]:
           player_id = player["UserId"] 
    return player_id

def get_rake(s, mail):
    date_from = '2020-01-15'#input("From which time (format daty 2020-03-20)? ")#T00:00:00.000Z'
    date_to =  datetime.datetime.now().strftime('%Y/%m/%d') #'2020-03-23'#T00:00:00.000Z'
    rake_data = {"SearchEmail": mail, "DateBegin":date_from,"DateEnd":date_to,"PageSize": "20"}
    rake_url = "http://ggpoker.ggcore.net/api/get/GetPokerGGRReportRequest"
    r = ''
    r = s.post(rake_url, json=rake_data)
    rake_summary = json.loads(r.content)['Summary']
    for key, value in rake_summary.items():
        if "TotalCount" not in key:
            print(key, value)
        

def get_balance_history(s, player_id):
    date_from = '2020-01-22'#input("From which time (format daty 2020-03-20)? ")#T00:00:00.000Z'
    date_to =  datetime.datetime.now().strftime('%Y/%m/%d') #'2020-03-23'#T00:00:00.000Z'
    balance_data = {"DateBegin":date_from,"DateEnd":date_to,"PageSize":"200","UserId":player_id,"AgentName":AgentName,"DatePicker":"null","Type":"0","CurrentPage":"0"}
    balance_url = "http://ggpoker.ggcore.net/api/get/GetPlayerBalanceHistoryRequest"
    r = ''
    r = s.post(balance_url, json=balance_data)

    #Variables
    spiny1_balance = 0
    spin1_played = 0
    spiny5_balance = 0
    spin5_played = 0
    spiny20_balance = 0
    spin20_played = 0
    spiny50_balance = 0
    spin50_played = 0
    spins_total = 0
    spins_total_played = 0
    cash_balance = 0
    mtt_balance = 0
    test = 0
    #transfers
    player_transfers = 0
    agent_transfers = 0
    deposit_total = 0 
    rakeback = 0
    audyt = json.loads(r.content)['List']

    for row in audyt:
        if 'Spin & Gold #1' in row['Description']:
            spiny1_balance += row['Amount']   
            if "Buyin" in row['Description']:
                     spin1_played +=1
            if "Unregister " in row['Description']:
                     spin1_played -=1  
        if 'Spin & Gold #2' in row['Description']:
            spiny5_balance += row['Amount']
            if "Buyin" in row['Description']:
                     spin5_played +=1
            if "Unregister " in row['Description']:
                     spin5_played -=1  
        if 'Spin & Gold #3' in row['Description']:
            spiny20_balance += row['Amount']
            if "Buyin" in row['Description']:
                     spin20_played +=1
            if "Unregister " in row['Description']:
                     spin20_played -=1          
        if 'Spin & Gold #4' in row['Description']:
            spiny50_balance += row['Amount']
            if "Buyin" in row['Description']:
                     spin50_played +=1
            if "Unregister " in row['Description']:
                     spin50_played -=1  
        if row['Type']==1:
            cash_balance += row['Amount']
        if row['Type']==2:
            spins_total += row['Amount']
            if "Buyin" in row['Description']:
                     spins_total_played +=1
            if "Unregister " in row['Description']:
                     spins_total_played -=1
            if "Prize" in row['Description'] or "Complete" in row['Description']:
                     test +=1  
        if row['Type']==3:
            mtt_balance += row['Amount']
        if row['Type']==7:
            agent_transfers += row['Amount']
        if row['Type']==11:
            player_transfers += row['Amount']
        if row['Type']==20:
            rakeback += row['Amount']
        if row['Type']==25:
            deposit_total += row['Amount']

    print("Spins total profit = %.2f" % spins_total)
    print("Spins total played = %.2f" % spins_total_played)
    print("Cash games profit = %.2f" % cash_balance)
    print("MTT profit = %.2f" % mtt_balance)
    print("Agent transfers = %.2f" % agent_transfers)
    print("Player transfers = %.2f" % player_transfers)
    print("Deposits = %.2f" % deposit_total)
    print("Rakeback = %.2f" % rakeback)

def get_player_token(s, mail):
    player_id = get_player_id(s, mail=mail)
    token_data = {"AgentName":AgentName,"UserId":player_id}
    token_url = 'http://ggpoker.ggcore.net/api/get/GetPokerCraftTokenRequest'
    token = json.loads(s.post(token_url, json = token_data).text)['Token']
    return token

def get_auth_token(token):
    url = "https://my.pokercraft.com/api/auth?platform=client&gp-token={}".format(token)
    payload = {}
    headers= {}
    response = requests.request("GET", url, headers=headers, data = payload)
    token1= json.loads(response.text)['token']
    return token1

def get_aes_key(auth_token):
    decoded = jwt.decode(auth_token, verify=False)
    password = "{}{}".format(decoded['jti'],decoded['exp']).encode()
    return password

def decode_response(message, key):
    ct_b64 = base64.b64decode(message.text)
    pt = decrypt(ct_b64, key)
    return pt


def get_sessions(token_auth, fromTime, toTime):
    
    hh_url = "https://my.pokercraft.com/api/handhistory/list/session"
    fromTime = str(int(datetime.datetime.strptime(fromTime, r"%d/%m/%Y").timestamp()*1000))
    toTime = str(int(datetime.datetime.strptime(toTime, r"%d/%m/%Y").timestamp()*1000))

    session_data = {"gameKind":"SpinAndGold","fromTime":fromTime,"toTime":toTime,"itmOnly":"null","condition":"null"}
    headers = {"Authorization": "Bearer {}".format(token_auth)}
    response = requests.request("POST", hh_url, headers=headers, json=session_data)
    
    password = get_aes_key(token_auth)


    pt = decode_response(response, password)

    
    sessions = json.loads(json.loads(pt.decode('utf-8')))
    #print(f'Number of tournaments {len(sessions)}')
    sessionsIds = []
    for item in sessions:
        sessionId = item['sessionId']
        sessionsIds.append(sessionId)
    return sessionsIds
    #print(sessions1)
    #sessionIds = ', '.join([str(x['sessionId']) for x in sessions]).strip()
    #print(sessionIds)


def get_download_link(token_auth, sessionsIds):
    download_url = 'https://my.pokercraft.com/api/handhistory/list/download'
    download_data = {"sessionlist": sessionsIds}
    headers = {"Authorization": "Bearer {}".format(token_auth)}


    response = requests.request("PUT", download_url, headers=headers, json=download_data)
    
    password = get_aes_key(token_auth)
    link = json.loads(json.loads(decode_response(response,password).decode('utf-8')))['code']
    return 'https://my.pokercraft.com/embeded/download/?lang=en&code={}'.format(link)

def get_download_links(token_auth, sessionIds):
    slices = round(len(sessionIds)/500)+1
    sessions = np.array_split(sessionIds, slices)
    links = []
    for a in sessions:
        session_to_download = ', '.join(a)
        links.append(get_download_link(token_auth, session_to_download))
    return links

def download_hhs(mail, date_from, date_to):
    s = login()
    mail = mail
    token = get_player_token(s, mail)
    token_auth = get_auth_token(token)
    sessions = get_sessions(token_auth,date_from,date_to)

    links = get_download_links(token_auth, sessions)
    return links



""" client = discord.Client()

@client.event
async def on_ready():
    print("Logged in")
    #print(f"We have logged in as{client.user}")

@client.event
async def on_message(message):  # event that happens per any message.

    # each message has a bunch of attributes. Here are a few.
    # check out more by print(dir(message)) for example.
    #print(f"{message.channel}: {message.author}: {message.author.name}: {message.content}")

    if "!hh" in message.content.lower():
        dane = message.content.split(",")
        mail = dane[0][4::]
        date_from = dane[1].strip()
        date_to = dane[2].strip()
        links = download_hhs(mail, date_from, date_to)
        #hand = message.content.upper()
        #calcu = nash_calcs(1, hand[3:5])
        for link in links:
            await message.channel.send(link)
        await message.channel.send('DONE!')

client.run("xxxx") */

#client id xxxxxx
#token xxxxx
#xxx
#https://discordapp.com/oauth2/authorize?client_id=xxxx
"""

s = login()
mail = 'mail@host.com'#input('Podaj maila?')
player_id = get_player_id(s,mail)
get_rake(s, mail)
get_balance_history(s, player_id)
