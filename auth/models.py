# auth/models.py

from flask_login import UserMixin

class User(UserMixin):
    def __init__(self, id, username, password, email="", security_question="", security_answer=""):
        self.id = id
        self.username = username
        self.password = password
        self.email = email
        self.security_question = security_question
        self.security_answer = security_answer

    @staticmethod
    def from_db_row(row):
        if row:
            return User(
                id=row[0],
                username=row[1],
                password=row[2],
                email=row[3],
                security_question=row[4],
                security_answer=row[5]
            )
        return None