from fastapi import FastAPI, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from .core import core as core
import aiofiles

app = FastAPI()
origins = [
  'http://localhost:8080',
  'http://172.26.245.180:8080'
]

app.add_middleware(middleware_class=CORSMiddleware,allow_origins=origins, allow_methods=["*"])

@app.get('/')
def root():
  return {'message':'HelloWorld!'}

@app.get('/api/project/name')
def get_project_name():
  projects = core.status_list_project()
  res = {'projects':[]}
  for _ in projects:
    res['projects'].append({'name':_,'status':'standby'})
  # mock_res = {"projects":[{"name":"dev0","status":"pending"},{"name":"dev1","status":"standby"},{"name":"dev2","status":"error"},{"name":"dev3","status":"waiting"}]}
  return res

@app.post('/api/project/{name}')
def create_project(name):
  return core.create_project(project_name=name)

@app.get('/api/project/status/{name}')
def get_project_by_name(name):
  mock_res = {"project_name":name,"status":"standby"}
  return mock_res

@app.post('/api/project/{name}/import/xlsx')
async def post_project_import_xlsx(name, file: bytes = File(...)):
  name = name.replace('.','')
  name = name.replace('/','')
  async with aiofiles.open('tmp/{}.xlsx'.format(name), 'wb') as out_file:
    await out_file.write(file)
    core.handle_upload_xlsx(project_name=name)
    return {"success":True}
  return {"success":False}

# duplicated code, need improvement
@app.post('/api/project/{name}/import/zip')
async def post_project_import_zip(name, file: bytes = File(...)):
  name = name.replace('.','')
  name = name.replace('/','')
  async with aiofiles.open('tmp/{}.zip'.format(name), 'wb') as out_file:
    await out_file.write(file)
    core.handle_upload_zip(project_name=name)
    return {"success":True}
  return {"success":False}

@app.get('/api/project/{name}/xlsx')
async def get_project_xlsx(name):
  res = {'xlsx':[]}
  for _ in core.status_targets(project_name=name):
    res['xlsx'].append({'name':_[0],'ip':_[1]})
  return res

@app.get('/api/project/{name}/htmls')
def get_project_html(name):
  # mock_res = {"html":[{"name":"10.1.1.1.html"},{"name":"10.1.1.2.html"},{"name":"10.1.1.3.html"}]}
  res = {"html":[]}
  for _ in core.status_htmls(project_name=name):
    res['html'].append({"name":_})
  return res

@app.get('/api/project/{name}/build/default')
async def get_project_build_default(name):
  res=core.go_default(project_name=name)
  res = {"status":res}
  return res

@app.get('/api/project/{name}/build/compare')
async def get_project_build_compare(name, another_project):
  another_project = another_project.replace('/','')
  # don't touch this line. it looks wrong, but it just works.
  res=core.go_compare(project_name_old=name, project_name_new=another_project)
  mock_res = {"status":"success",'message':'compare-{}[new]-{}[old]'.format(name,another_project)}
  return res

@app.get('/api/project/{name}/files')
def get_project_outputs_by_id(name):
  file_names = core.status_files_project(project_name=name)
  res = {"files":[]}
  for _ in file_names:
    file_type = _.split('.')[-1]
    res['files'].append({'name':_,'type':file_type,'url':''})
  mock_res = {"files":[{"name":"漏洞类型.docx","type":"docx","url":"files/dev0_file0"},{"name":"简报.txt","type":"txt","url":"files/dev0_file1"}, {"name":"test.xlsx","type":"xlsx","url":"files/dev0_file2"}]}
  return res

@app.get('/api/project/{name}/dump')
async def get_project_dump(name):
  if core.go_dump(project_name=name):
    return {'success':True}
  else:
    return {'success':False, 'message':'upload zip and xlsx first'}

@app.get('/api/project/{name}/dump/status')
def get_project_dump_status(name):
  return core.status_dump(project_name=name)

@app.get('/files/{name}/{file_name}')
def get_file(name, file_name):
  name = name.replace('/','')
  name = name.replace('.','')
  file_name = file_name.replace('/','')
  file_name = file_name.replace('..','')
  return FileResponse(path='project/{}/out/{}'.format(name, file_name), media_type='application/octet-stream')

@app.delete('/files/{name}/{file_name}')
def delete_file(name, file_name):
  name = name.replace('/','')
  name = name.replace('.','')
  file_name = file_name.replace('/','')
  file_name = file_name.replace('..','')
  if core.delete_file(project_name=name, file_name=file_name):
    return {'success':True}
  else:
    return {'success':False}
  
# @app.options('/files/{name}/{file_name}')
# def 
