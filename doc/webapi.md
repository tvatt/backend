## Web API calls
- `GET /api/board`
  it is public call to read board it return array of json with values date and slot and who booked it
  return ex.
```json
[
    {
        "id": 12,
        "day": "2021-03-20",
        "slot": 2,
        "username": "amer",
        "unitNo": "u2"
    },
    {
        "id": 14,
        "day": "2021-03-20",
        "slot": 1,
        "username": "user",
        "unitNo": ""
    },
    {
        "id": 15,
        "day": "2021-03-21",
        "slot": 1,
        "username": "john",
        "unitNo": "u11"
    }
]
```

- `POST /api/board`
  it need Basic Auth in the header, it will use the auth to know which username makes or change current booking and read from the body the day and slot value
  ex. of body
```json
{
"day": "2021-03-21",
"slot": 2
}
```
it return OK 200 when success and 401 or 500 otherwise

- `DELETE /api/board`
  like the above, but it does not need body as it will delete all appointment for the username that call it

- `DELETE /api/board/:username`
  like the above but will be used by admin to remove a booking, so it takes path variable `:username` to specified which user

- `GET /api/user`
  it will return array of json of all users' info, it needs admin credential, passwords are not included also admin info won't be included
  ex. of return
```json
[
    {
        "id": 4,
        "unitNo": "u2",
        "username": "user4"
    },
    {
        "id": 5,
        "unitNo": "u4",
        "username": "u4"
    },
    {
        "id": 6,
        "unitNo": "u9",
        "username": "u9"
    }
]
```
- `GET /api/user/:username`
  like the above one but it will only return the info of one user and it can be call by admin or the username itself

- `POST /api/login/`
  its simple call that return OK 200 if the caller were authenticated otherwise it will return 401

- `POST /api/user`
  it needs admin authentication, used to sign up new user to the system, it takes json in the body for user info

ex. body
```json
{
    "unitNo":"u11",
    "username":"user11",
    "password":"12345678"
}
```

- `DELETE /api/user/:userId`
  it needs admin authentication, used to remove user from the system, it takes path variable `:userId` to specify which user to delete

- `POST /api/user/resetpassword/:userId`
  it needs admin authentication, used to reset user password, it takes path variable `:userId` to specify which user and it takes body json to specify new password
  ex. of body
```json
{
    "password": "12345678"
}
```

- `POST /api/user/changepassword`
  it called by the user itself to change own password, need body like reset password call with new password

- `PUT /api/user/:userId`
  it called by the user itself to change the info that they are allowed to change, the user is only allowed to change their username, it take body json for new info
  body ex.
```json
{
    "username": "newUsername11"
}
```
- `GET /api/statistics`
  it needs admin or statistician authentication to get statistics values in json format
  response ex.
```json
[
    {
        "action": "Login",
        "count": "45"
    },
    {
        "action": "Change Booking",
        "count": "114"
    },
    {
        "action": "get Board",
        "count": "215"
    },
    {
        "action": "Change Password",
        "count": "1"
    }
]
```
