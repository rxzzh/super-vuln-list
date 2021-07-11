import sqlite3
import logging
from utils import singleton
from rich import print
from functools import cached_property

@singleton
class DB:
    def __init__(self):
        db_filename = 'db.sqlite'
        self.conn = sqlite3.connect(db_filename)
        logging.info('s')

    # def execute(self, sql):
    #     c = self.conn.cursor()
    #     res = c.execute(sql)
    #     self.conn.commit()
    #     return res

    def execute(self, sql: str, values: tuple):
        # print('[blue][SQL]{}\n[green][VALUES]{}\n'.format(sql, values))
        c = self.conn.cursor()
        res = c.execute(sql, values)
        self.conn.commit()
        return res


class SchemaManager:
    def __init__(self):
        self.db = DB()
        if 'db.sqlite' not in os.listdir():
            SchemaManager().init_tables()

    def reset_database(self):
        self.drop_all_tables()
        self.init_tables()

    def load_toy_table(self):
        project_insert = 'insert into project values (null, "{project_name}");'
        host_insert = 'insert into host values (null, {project_id}, "{name}", "{ip}");'
        vuln_insert = 'insert into vuln values (null, "{name}", {severity});'
        host_vuln_insert = 'insert into host_vuln values ({host_id}, {vuln_id});'

        projects = [
            ['dev0'],
            ['dev1'],
            ['dev2'],
        ]

        hosts = [
            [1, 'host_0_0', '1.1.1.1'],
            [1, 'host_0_1', '1.1.1.2'],
            [2, 'host_1_0', '1.1.2.1'],
            [2, 'host_1_1', '1.1.2.2'],
            [3, 'host_1_0', '1.1.2.1'],
            [3, 'host_1_1', '1.1.2.2'],
        ]

        vulns = [
            ['vuln_a', 1],
            ['vuln_b', 2],
            ['vuln_c', 3]
        ]

        host_vulns = [
            [1, 1],
            [1, 2],
            [1, 3],
            [2, 1],

            [3, 1],
            [3, 2],
            [3, 3],
            [3, 3],
            [4, 2],
            [4, 1],

            [5, 1],
            [5, 2],
            [5, 3],
            [5, 3],
            [6, 2],
            [6, 3]

        ]
        for project in projects:
            self.db.execute(project_insert.format(project_name=project[0]), ())

        for vuln in vulns:
            self.db.execute(vuln_insert.format(
                name=vuln[0], severity=vuln[1]), ())

        for host in hosts:
            self.db.execute(host_insert.format(
                project_id=host[0], name=host[1], ip=host[2]), ())

        for host_vuln in host_vulns:
            self.db.execute(host_vuln_insert.format(
                host_id=host_vuln[0], vuln_id=host_vuln[1]), ())

    def init_tables(self):
        init_table_sqls = [
            '''create table host (
                id integer primary key autoincrement,
                project_id integer,
                ip char(50) not null,
                scan boolean default 0,
                foreign key (project_id) references project(id)
            );''',
            '''create table project(
                id integer primary key autoincrement,
                name text not null unique
            );''',
            '''create table vuln(
                id integer primary key autoincrement,
                name text not null unique,
                severity text not null
            );''',
            '''create table host_vuln(
                host_id integer,
                vuln_id integer,
                foreign key (host_id) references host(id),
                foreign key (vuln_id) references vuln(id)
            );''',
            '''create table target(
                id integer primary key autoincrement,
                project_id integer,
                name text not null,
                ip text,
                purpose
            )
            ''',
            '''create unique index host_unique_index on host(ip, project_id);
            '''
        ]
        for sql in init_table_sqls:
            self.db.execute(sql, ())

    def drop_all_tables(self):
        sqls = [
            'drop table host_vuln;',
            'drop table vuln;',
            'drop table host;',
            'drop table project;',
            'drop table target'
        ]
        for sql in sqls:
            self.db.execute(sql, ())


class MiddleLayer:
    def __init__(self):
        self.db = DB()

    def insert_project(self, project_name):
        sql = 'insert into project values (null, ?);'
        self.db.execute(sql, (project_name,))

    def insert_target(self, project_name, name, ip, purpose=''):
        project_id = self.query_project_id(project_name=project_name)
        sql = 'insert into target (project_id, name, ip, purpose) values (?, ?, ?, ?);'
        self.db.execute(sql, (project_id, name, ip, purpose))

    def insert_host(self, ip, project_name):
        project_id = self.query_project_id(project_name=project_name)
        sql = 'insert into host values (null, ?, ?, 0);'
        self.db.execute(sql, (project_id, ip))

    def insert_vuln(self, name, severity):
        sql = 'insert into vuln values (null, ?, ?);'
        self.db.execute(sql, (name, severity))

    def insert_host_vuln(self, project_name, host_ip, vuln_name):
        host_id = self.query_host_id(
            project_name=project_name, host_ip=host_ip)
        vuln_id = self.query_vuln_id(vuln_name=vuln_name)

        sql = 'insert into host_vuln values (?, ?);'
        self.db.execute(sql, (host_id, vuln_id))

    def update_host_scan_state(self, project_name, host_ip):
        project_id = self.query_project_id(project_name=project_name)
        sql = 'update host set scan=1 where project_id=? and ip=?'
        # print('ueah')
        self.db.execute(sql, (project_id, host_ip))
    
    def query_projects(self):
        sql = 'select name from project;'
        return self.db.execute(sql, ()).fetchall()

    def query_project_id(self, project_name):
        sql = 'select id from project where name = ?;'
        return self.db.execute(sql, (project_name,)).fetchone()[0]

    def query_vuln_id(self, vuln_name):
        sql = 'select id from vuln where name=?;'
        return self.db.execute(sql, (vuln_name,)).fetchone()[0]

    def query_host_id(self, project_name, host_ip):
        project_id = self.query_project_id(project_name=project_name)
        sql = 'select id from host where project_id=? and ip=?'
        return self.db.execute(sql, (project_id, host_ip)).fetchone()[0]

    def query_host_ids(self, project_name):
        project_id = self.query_project_id(project_name=project_name)
        sql = 'select id from host where project_id=?;'
        return self.db.execute(sql, (project_id,)).fetchall()

    def query_hosts(self, project_name):
        project_id = self.query_project_id(project_name=project_name)
        sql = 'select ip from host where project_id=?'
        return self.db.execute(sql, (project_id,)).fetchall()

    def query_hosts_scan(self, project_name):
        project_id = self.query_project_id(project_name=project_name)
        sql = 'select ip from host where project_id=? and scan=1'
        return self.db.execute(sql,(project_id,)).fetchall()

    def query_vulns(self, project_name):
        project_id = self.query_project_id(project_name=project_name)
        sql = '''select vuln.name, vuln.severity
                    from host_vuln as hv
                    left join host on hv.host_id=host.id
                    left join vuln on hv.vuln_id=vuln.id
                    where host.project_id=?
                    group by vuln.name;
              '''
        return self.db.execute(sql,(project_id,)).fetchall()

    def query_all_vulns(self):
        sql = '''select name, severity from vuln'''
        return self.db.execute(sql,()).fetchall()

    # TODO REWRITE
    def query_artifact_TARGETS(self, project_name):
        project_id = self.query_project_id(project_name=project_name)
        sql = '''select target.name, target.ip from target where project_id=?
              '''
        return self.db.execute(sql,(project_id,)).fetchall()
    
    def query_artifact_SCAN_TARGETS(self, project_name):
        project_id = self.query_project_id(project_name=project_name)
        sql = '''select target.name, target.ip
                 from (select * from target where project_id=?) as target
                 left join (select * from host where project_id=?) as host
                 on target.ip=host.ip
                 where host.scan=1
              '''
        return self.db.execute(sql, (project_id,project_id))


    def query_artifact_VULN_TYPE(self, project_name):
        project_id = self.query_project_id(project_name=project_name)
        sql = '''select vuln.name, vuln.severity, host.ip
                    from host_vuln
                    left join host on host_vuln.host_id=host.id
                    left join vuln on host_vuln.vuln_id=vuln.id
                    where host.project_id=?
                    order by vuln.severity, vuln.name
              '''
        return self.db.execute(sql,(project_id,)).fetchall()

    def query_artifact_VULN_COUNT(self, project_name):
        project_id = self.query_project_id(project_name=project_name)
        host_ids = self.query_host_ids(project_name=project_name)
        host_ids = list(map(lambda x: x[0], host_ids))
        sql = '''select 
                        (select count(*)
                            from host_vuln as hv
                            left join host on hv.host_id=host.id
                            left join vuln on hv.vuln_id=vuln.id
                            where vuln.severity='low' and host.id=?
                        ),
                        (select count(*)
                            from host_vuln as hv
                            left join host on hv.host_id=host.id
                            left join vuln on hv.vuln_id=vuln.id
                            where vuln.severity='middle' and host.id=?
                        ),
                        (select count(*)
                            from host_vuln as hv
                            left join host on hv.host_id=host.id
                            left join vuln on hv.vuln_id=vuln.id
                            where vuln.severity='high' and host.id=?
                        ),
                        (select count(*)
                            from host_vuln as hv
                            left join host on hv.host_id=host.id
                            left join vuln on hv.vuln_id=vuln.id
                            where host.id=?
                        )
              '''
        sql2 = 'select ip from host where id=?;'
        res = []
        for id_ in host_ids:
            res.append(self.db.execute(sql2, (id_,)).fetchone(
            ) + self.db.execute(sql,(id_,id_,id_,id_)).fetchone())
        return res

    # def query_artifact_COMPARE(self, project_name_a, project_name_b):
    #     pass

# sm = SchemaManaer()
# sm.reset_database()
# sm.load_toy_table()
