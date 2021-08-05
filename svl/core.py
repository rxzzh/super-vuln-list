from orchestra import User
import os
import re
import asyncio
class Core:
    def __init__(self):
        self.uc = User(interactive=False)
        self.ml = self.uc.mc.ml
    
    def create_project(self, project_name):
        return self.uc.generate_project(project_name)
    
    def delete_project(self, project_name):
        pass
    
    def import_project_xlsx(self, project_name):
        pass

    def import_project_zip(self, project_name):
        pass

    def go_dump(self, project_name):
        if not self.uc.environment_check(project_name=project_name):
            return False
        self.uc.mc.db_dump(project_name=project_name)

    def go_default(self, project_name):
        self.uc.go(project_name=project_name)

    def go_compare(self, project_name_old, project_name_new):
        self.uc.compare(project_name_0=project_name_new, project_name_1=project_name_old)

    def status_dump(self, project_name):
        pass
    
    def status_ready_project(self, project_name):
        pass

    def status_list_project(self):
        return self.uc.list_projects()

    def status_files_project(self, project_name):
        return os.listdir('project/{}/out/'.format(project_name))
    
    def status_targets(self, project_name):
        try:
            return self.ml.query_artifact_TARGETS(project_name=project_name)
        except TypeError:
            return []
    
    def status_htmls(self, project_name):
        return os.listdir('project/{}/hosts/'.format(project_name))

    def status_hosts(self, project_name):
        res = {''}

    def delete_file(self, project_name, file_name):
        try:
          os.remove('project/{}/out/{}'.format(project_name, file_name))
          return True
        except FileNotFoundError:
          return False
    
    def handle_upload_xlsx(self, project_name):
        safe_re = re.compile(pattern=r'^[a-z|A-Z|0-9|-]+$')
        if not safe_re.match(project_name):
            print('regex fail')
            return False
        os.system('mv tmp/{}.xlsx project/{}/targets_xlsx/properties.xlsx'.format(project_name, project_name))
        self.uc
        return True

    def handle_upload_zip(self, project_name):
        safe_re = re.compile(pattern=r'^[a-z|A-Z|0-9|-]+$')
        if not safe_re.match(project_name):
            print('regex fail')
            return False
        os.system('rm -rf project/{}/hosts'.format(project_name))
        os.system('unzip -qq tmp/{}.zip "host/*.html" -d project/{}/'.format(project_name, project_name))
        os.system('mv project/{}/host project/{}/hosts'.format(project_name, project_name))
        return True
core = Core()

# res=core.status_list_project()
# res=core.go_default(project_name='dev')
# print(res)