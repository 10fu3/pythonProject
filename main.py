import uuid

from fastapi import FastAPI
from fastapi.responses import RedirectResponse
import urllib.parse
import urllib.request
import uvicorn
import requests
import jwt

app = FastAPI()
stateMap = dict()
apiServer = "http://localhost"
client_id = "3bdbf32c-7305-474e-a99e-e8fede66e7b3"
client_secret = "754ace4b-cde0-4128-8210-b0aa684ddb43"


@app.get("/callback")
async def loginCallBack(code: str, state: str):
    if state in stateMap:
        nonce = str(stateMap.get(state)["nonce"])
        result = requests.post(apiServer + "/oauth2/v1/token", data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "http://localhost:4000/callback",
            "client_id": client_id,
            "client_secret": "754ace4b-cde0-4128-8210-b0aa684ddb43"
        })
        decoded_id_token = jwt.decode(result.json()["id_token"],
                                      client_secret,
                                      audience=client_id,
                                      issuer='http://localhost',
                                      algorithms=["HS256"])
        expected_nonce = decoded_id_token.get('nonce')
        if nonce != expected_nonce:
            raise RuntimeError('invalid nonce')
        else:
            return decoded_id_token.items()

@app.get("/login")
def login():
    baseurl = apiServer + ":3000/oauth2/v1/authorize"
    redirect_url = "http://localhost:4000/callback"
    scope = "openid profile"
    nonce = str(uuid.uuid4())
    state = str(uuid.uuid4())
    params = {"response_type": "code",
              "client_id": client_id,
              "redirect_uri": redirect_url,
              "state": state,
              "scope": scope,
              "nonce": nonce
              }
    url = '{}?{}'.format(baseurl, urllib.parse.urlencode(params))

    stateMap[state] = {
        "nonce": nonce
    }

    return RedirectResponse(url)


@app.get("/")
def read_root():
    return {"Hello": "World"}


def main():
    uvicorn.run(app, host="0.0.0.0", port=4000)


if __name__ == '__main__':
    main()
