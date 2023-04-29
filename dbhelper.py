import mysql.connector as connector

class DBhelper:

    def __init__(self):
        self.con = connector.connect(host='localhost',
                                     port='3306',
                                     user='root',
                                     password='Manulis13615@',
                                     database='pythontest')

        query = 'create table if not exists user(userId int primary key, userName varchar(200), phone varchar(12))'

        with self.con.cursor() as cur:
            cur.execute(query)
        
        print("Created")

    # insert
    def insert_user(self, userid, username, phone):
        query = "insert into user(userId, userName, phone) values({},'{}','{}')".format(userid, username, phone)
        print(query)
        cur = self.con.cursor()
        cur.execute(query)
        self.con.commit()
        print("user saved to db")

    # fetch all
    def fetch_all(self):
        query = "select * from user"
        cur = self.con.cursor()
        cur.execute(query)
        for row in cur:
            print("userId: ", row[0])
            print("userName: ", row[1])
            print("phone: ", row[2])
            print()

    # delete
    def delete_user(self, userId):
        query = "delete from user where userId = {}".format(userId)
        print(query)
        cur = self.con.cursor()
        cur.execute(query)
        self.con.commit()
        print("user deleted from db")

    # update
    def update_user(self, userId, newName, newPhone):
        query = "update user set userName = '{}', phone = '{}' where userId = {}".format(newName, newPhone, userId)
        print(query)
        cur = self.con.cursor()
        cur.execute(query)
        self.con.commit()
        print("user updated in db")