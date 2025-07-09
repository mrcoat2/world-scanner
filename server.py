from http.server import BaseHTTPRequestHandler, HTTPServer

import sqlite3
import json
import ast

conn = sqlite3.connect("ports.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS tcp_ports (
    ip TEXT,
    port INTEGER,
    state TEXT,
    reason TEXT,
    name TEXT,
    product TEXT,
    version TEXT,
    extrainfo TEXT,
    conf TEXT,
    cpe TEXT,
    scripts TEXT
)
""")
conn.commit()

current_address = "1.1.1.48"

def get_next_ip():
    global current_address
    found = True
    while found:
        address_array = current_address.split('.')
        address_array[3] = str(int(address_array[3])+1)
        current_address = ""
        i = 3
        while not i == -1:
            
            if address_array[i] == "256":
                address_array[i-1] = str(int(address_array[i-1])+1)
                address_array[i] = "1"

            i -= 1
        
        current_address = '.'.join(address_array)
        cursor.execute("SELECT 1 FROM tcp_ports WHERE ip = ? LIMIT 1", (current_address,))
        found = cursor.fetchone()
    return current_address
    
def sql_escape(val):
    if val is None:
        return 'NULL'
    return "'" + str(val).replace("'", "''") + "'"

class MyHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == "/ips":
            print("New Connect")
            length = int(self.headers.get('Content-Length', 0))
            
            data = self.rfile.read(length).decode()
            data = json.loads(data)

            for port, info in data['tcp'].items():
                sql = f"""INSERT INTO tcp_ports (
                    ip, port, state, reason, name, product, version, extrainfo, conf, cpe, scripts
                ) VALUES (
                    {sql_escape(self.headers.get('scanned', 0))},
                    {port},
                    {sql_escape(info.get('state'))},
                    {sql_escape(info.get('reason'))},
                    {sql_escape(info.get('name'))},
                    {sql_escape(info.get('product'))},
                    {sql_escape(info.get('version'))},
                    {sql_escape(info.get('extrainfo'))},
                    {sql_escape(info.get('conf'))},
                    {sql_escape(info.get('cpe'))},
                    {sql_escape(json.dumps(info.get('script', {})))}
                );"""
                cursor.execute(sql)
                conn.commit()

            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"IP saved.\n")
        else:
            self.send_error(404, "Not Found")

    def do_GET(self):
        if self.path == "/todo":
            try:
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(current_address)))
                self.end_headers()
                self.wfile.write(current_address.encode())
                get_next_ip()
            except FileNotFoundError:
                self.send_error(404, "todo.txt not found")
        else:
            self.send_error(404, "Not Found")

def run(server_class=HTTPServer, handler_class=MyHandler, port=8080):
    server = server_class(('', port), handler_class)
    print(f"Listening on port {port}...")
    server.serve_forever()

if __name__ == "__main__":
    run()
    conn.close()
