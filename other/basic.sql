create table host (
    id integer primary key autoincrement,
    project_id integer not null,
    name text not null,
    ip char(50) not null
);

create table project(
    id integer primary key autoincrement,
    name text not null
);

create table vuln(
    id integer primary key autoincrement,
    name text not null,
    severity integer not null
);

create table host_vuln(
    host_id integer,
    vuln_id integer
);

insert into project values (null, {project_name})
insert into host values (null, {project_id}, {name}, {ip});
insert into vuln values (null, {name}, {severity})
insert into host_vuln values ({host_id}, {vuln_id})