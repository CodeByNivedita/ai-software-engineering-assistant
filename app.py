from auth import is_authenticated

def login(token):
    if is_authenticated(token):
        return "Logged in"
    return "Invalid token"
