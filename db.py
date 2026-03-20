import pymysql

def get_db():

    return pymysql.connect(
        host="10.101.1.211",
        user="sysadmin",
        password="umivaupuhi",
        database="logcollector",
        cursorclass=pymysql.cursors.DictCursor
    )
