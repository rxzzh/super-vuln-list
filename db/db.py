import sqlite3
import logging


def singleton(class_):
    instances = {}

    def getinstance(*args, **kwargs):
        if class_ not in instances:
            instances[class_] = class_(*args, **kwargs)
        return instances[class_]
    return getinstance


@singleton
class DB:
    def __init__(self):
        db_filename = 'db.sqlite'
        self.conn = sqlite3.connect(db_filename)
        logging.info('s')

    def execute(self, sql):
        c = self.conn.cursor()
        res = c.execute(sql)
        self.conn.commit()
        return res


class MiddleLayer:
    def __init__(self):
        self.db = DB()

    def insert_project(self, project_name):
        sql = 'insert into project values (null, "{project_name}");'
        sql = sql.format(project_name=project_name)
        self.db.execute(sql)

    def insert_host(self, name, ip, project_name):
        sql = 'select id from project where name="{project_name}"'.format(project_name=project_name)
        res = self.db.execute(sql)
        project_id = res.fetchone()[0]
        sql = 'insert into host values (null, {project_id}, "{name}", "{ip}");'.format(project_id=project_id, name=name, ip=ip)
        self.db.execute(sql)

    def insert_vuln(self, name, severity):
        sql = 'insert into vuln values (null, "{name}", {severity});'.format(name=name, severity=severity)
        self.db.execute(sql)

    def insert_host_vuln(self,project_name, host_name, vuln_name):
        host_id = self.query_host_id(project_name=project_name, host_name=host_name)
        vuln_id = self.query_vuln_id(vuln_name=vuln_name)

        sql = 'insert into host_vuln values ({host_id}, {vuln_id});'.format(host_id=host_id, vuln_id=vuln_id)
        self.db.execute(sql)

    def query_project_id(self, project_name):
        sql = 'select id from project where name="{project_name}";'.format(project_name=project_name)
        return self.db.execute(sql).fetchone()[0]

    def query_vuln_id(self, vuln_name):
        sql = 'select id from vuln where name="{vuln_name}";'.format(vuln_name=vuln_name)
        return self.db.execute(sql).fetchone()[0]
    
    def query_host_id(self, project_name, host_name):
        project_id = self.query_project_id(project_name=project_name)
        sql = 'select id from host where project_id={project_id} and name="{host_name}"'.format(project_id=project_id, host_name=host_name)
        return self.db.execute(sql).fetchone()[0]

    def query_host_ids(self, project_name):
        project_id = self.query_project_id(project_name=project_name)
        sql = 'select id from host where project_id={project_id};'.format(project_id=project_id)
        return self.db.execute(sql).fetchall()

    def query_hosts(self, project_name):
        project_id = self.query_project_id(project_name=project_name)
        sql = 'select name, ip from host where project_id={project_id}'.format(project_id=project_id)
        return self.db.execute(sql).fetchall()

    def query_vulns(self, project_name):
        project_id = self.query_project_id(project_name=project_name)
        sql = '''select vuln.name, vuln.severity
                    from host_vuln as hv
                    left join host on hv.host_id=host.id
                    left join vuln on hv.vuln_id=vuln.id
                    where host.project_id={project_id}
                    group by vuln.name;
              '''.format(project_id=project_id)
        return self.db.execute(sql).fetchall()

    def query_artifact_TARGETS(self, project_name):
        project_id = self.query_project_id(project_name=project_name)
        sql = '''select host.name, host.ip 
                    from host 
                    where host.project_id={project_id} 
                    order by host.ip
              '''.format(project_id=project_id)
        return self.db.execute(sql).fetchall()

    def query_artifact_VULN_TYPE(self, project_name):
        project_id = self.query_project_id(project_name=project_name)
        sql = '''select vuln.name, vuln.severity, host.ip
                    from host_vuln
                    left join host on host_vuln.host_id=host.id
                    left join vuln on host_vuln.vuln_id=vuln.id
                    where host.project_id={project_id}
                    order by vuln.name
              '''.format(project_id=project_id)
        return self.db.execute(sql).fetchall()

    def query_artifact_VULN_COUNT(self, project_name):
        project_id = self.query_project_id(project_name=project_name)
        host_ids = self.query_host_ids(project_name=project_name)
        host_ids = list(map(lambda x: x[0], host_ids))
        sql = '''select 
                        (select count(*)
                            from host_vuln as hv
                            left join host on hv.host_id=host.id
                            left join vuln on hv.vuln_id=vuln.id
                            where vuln.severity=1 and host.id={host_id}
                        ),
                        (select count(*)
                            from host_vuln as hv
                            left join host on hv.host_id=host.id
                            left join vuln on hv.vuln_id=vuln.id
                            where vuln.severity=2 and host.id={host_id}
                        ),
                        (select count(*)
                            from host_vuln as hv
                            left join host on hv.host_id=host.id
                            left join vuln on hv.vuln_id=vuln.id
                            where vuln.severity=3 and host.id={host_id}
                        ),
                        (select count(*)
                            from host_vuln as hv
                            left join host on hv.host_id=host.id
                            left join vuln on hv.vuln_id=vuln.id
                            where host.id={host_id}
                        )
              '''
        sql2 = 'select name, ip from host where id={id};'
        res = []
        for id_ in host_ids:
            res.append(self.db.execute(sql2.format(id=id_)).fetchone() + self.db.execute(sql.format(host_id=id_)).fetchone())
        return res

    def query_artifact_COMPARE(self, project_name_a, project_name_b):
        pass


# ml = MiddleLayer()
# # ml.insert_project(project_name='dev3')
# # ml.insert_host(name='test2', ip='2.1.1.2', project_name='dev3')
# # ml.insert_vuln(name='cve1', severity=1)
# # ml.insert_host_vuln(project_name='dev3', host_name='test2', vuln_name='cve1')
# from rich import print
# print(ml.query_hosts(project_name='dev1'))
# print(ml.query_vulns(project_name='dev3'))
# print(ml.query_artifact_TARGETS(project_name='dev2'))
# print(ml.query_artifact_VULN_TYPE(project_name='dev1'))
# print(ml.query_artifact_VULN_COUNT(project_name='dev0'))