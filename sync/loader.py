import json
import hashlib

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict


class SynMode(Enum):
    """
    数据 sync 的 type.

    Attributes:
        FULL: 全量 sync
        INCRE: 增量 sync
    """
    FULL = 1
    INCRE = 2


def dict_to_dataclass(cls, data):
    """将 dict 转换为 dataclass 对象"""
    field_types = {f.name: f.type for f in cls.__dataclass_fields__.values()}
    kwargs = {}
    for field, field_type in field_types.items():
        if field == 'model':
            kwargs[field] = data.get(field)
            continue
        if isinstance(data.get(field), dict):
            kwargs[field] = dict_to_dataclass(field_type, data[field])
        else:
            kwargs[field] = data.get(field)
    return cls(**kwargs)


def calculate_config_checksum(task_json):
    """
    对 json 对象进行 hash check 以检查唯一性.
    
    Args:
        task_json: 单个 task 的以 json 格式存储的info.

    Returns:
        对应 json 的 checksum.
    """
    json_to_str = json.dumps(task_json, sort_keys=True)
    sha1 = hashlib.sha1()
    sha1.update(json_to_str.encode('utf-8'))
    return sha1.hexdigest()


def get_fields(fields_str):
    """
    获取以 comma 分隔的 str 中的各个 fields.
    
    
    Args:
        fields_str: 以 comma 分隔的字符串.

    Returns:
        分割后得到的 fields 组成的 list.
    """
    return [field.strip() for field in fields_str.split(',')]


class FileLoader:
    """Load 指定文件, 目的是省略在 caller 中的 with clause"""

    @staticmethod
    def load(file_path):
        with open(file_path, 'r', encoding='utf-8') as file:
            return file.read()


class JSONParser:
    """
    Parse 以 json 格式存储的 config 文件信息.

    Attributes:
        _data: 对应的文件 content.
    """

    def __init__(self, data):
        self._data = data

    def get_main_info(self):
        """获取主信息, 为第一层的指定 keys 对应的 info."""
        keys_to_extract = ['name', 'description', 'source', 'target']
        return {key: self._data[key] for key in keys_to_extract}

    def get_task_info_list(self):
        """获取各个 tasks 的 info, 即第一层 key 为 tasks 的相关 info."""
        tasks = self._data['tasks']
        for task in tasks:
            self._process_task_fields(task, 'source')
            self._process_task_fields(task, 'target')
        return tasks

    def _process_task_fields(self, task, key):
        """
        处理 task 中的 fields 信息.

        如果指定了 primary key, 那么为了后面的 data sync 的方便, 会将 primary key
        统一放置在 fields 属性中的最后一个位置.

        Args:
            task: 单个 task 对应的 json info.
            key: task 下的 source 部分还是 target 部分.
        """
        fields = get_fields(task[key]['fields'])
        primary_key = task[key]['primary_key'].strip()
        if primary_key:
            task[key]['fields'] = self._resort_fields(fields, primary_key)

    def _resort_fields(self, fields_list, key):
        """
        对 fields 进行重排以将 primary key 放置在最后一个位置.

        Args:
            fields_list: 由各个 fields 组成的 list.
            key: 需要被放置在最后一个位置的 field.

        Return:
            以 comma 分隔的 fields 组成的 str.
        """
        fields_list.remove(key)
        fields_list.append(key)
        return ",".join(fields_list)


def get_enum_value_list(cls):
    """获取 Enum 类下 Attrs 的 value."""
    return [item.value for item in cls]


class FilterType(Enum):
    INT = 'int'
    TIME = 'time'


class KeyType(Enum):
    PRIMARY_KEY = 'primary_key'
    FILTER_KEY = 'filter_key'
    FILTER_KEY_TYPE = 'filter_key_type'


class JSONValidator:
    """
    对 json 配置文件信息进行 validate.
    
    [2024-09-02 1426] 该功能有待商榷, 目前不作 explain.
    """

    def __init__(self, config_json):
        self._json = config_json

    def validate(self):
        self._validate_task_keys()

    def _validate_task_keys(self):
        tasks = self._json['tasks']
        for task in tasks:
            self._single_validate(task, 'source')
            self._single_validate(task, 'target')
            self._cross_validate(task)

    def _single_validate(self, task, key):
        fields = get_fields(task[key]['fields'])
        primary_key = task[key].get('primary_key', '').strip()
        filter_key = task[key].get('filter_key', '').strip()
        filter_key_type = task[key].get('filter_key_type', '').strip()

        if filter_key and (not primary_key or not filter_key_type):
            raise ValueError(f"filter key, primary key and type"
                             "must both have or not have values.")

        self._validate_key_in_fields(primary_key, fields)
        # self._validate_key_in_fields(filter_key, fields)
        self._validate_key_in_fields(
            filter_key_type,
            get_enum_value_list(FilterType))

    def _validate_key_in_fields(self, key, fields):
        if key and key not in fields:
            raise ValueError(f"primary key or filter key not in fields.")

    def _cross_validate(self, task):
        source = task['source']
        target = task['target']
        key_list = get_enum_value_list(KeyType)
        for key in key_list:
            self._cross_validate_key(source, target, key)

    def _cross_validate_key(self, source, target, key):
        if bool(source.get(key, '')) != bool(target.get(key, '')):
            raise ValueError(f"source and target must both have "
                             f"or not have {key} value")
        

class JSONLoader:
    """
    加载指定的 config 文件以 json 格式存储.

    Attributes:
        _field_path: 文件 path.
        _origin_json: 原格式的 json 配置信息.
        _main_info: json 配置信息中的主信息, 主要指任务和连接信息.
        _task_info_list: 配置信息中的各个 task json 信息以 list 存储.
    """

    def __init__(self, file_path):
        """
        Args:
            file_path: 文件 path.
        """
        self._file_path = file_path
        self._origin_json = None
        self._main_info = None
        self._task_info_list = None
        self.load()

    def load(self):
        """对 class 中的 attrs 进行 initialization."""
        file_content = FileLoader.load(self._file_path)
        self._origin_json = json.loads(file_content)
        self._validate()
        self._parse()

    def _validate(self):
        """对 json 配置文件 content 进行 validate."""
        validator = JSONValidator(self._origin_json)
        validator.validate()

    def _parse(self):
        """按预定逻辑对 json 配置文件 content 进行 parse."""
        parser = JSONParser(self._origin_json)
        self._main_info = parser.get_main_info()
        self._task_info_list = parser.get_task_info_list()

    @property
    def main_info(self):
        return self._main_info

    @property
    def task_info_list(self):
        return self._task_info_list
    

@dataclass
class Target:
    """task 配置信息中的 target 部分."""
    table: str
    fields: str
    primary_key: str = ""
    filter_key: str = ""
    after_run_sql: str = ""


@dataclass
class Source:
    """task 配置信息中的 source 部分."""
    table: str
    fields: str
    primary_key: str = ""
    filter_key: str = ""
    filter_string: List[str] = field(default_factory=list)
    model: Dict = field(default_factory=dict)
    order_string: str = ""
    limit: str = ""


@dataclass
class TaskBase:
    """task 配置信息中的基础信息."""
    task_name: str
    source: Source
    target: Target
    schedule_time: str
    config_checksum: str


@dataclass
class Task(TaskBase):
    """
    将 task 信息转换为 task 实例任务.

    Attributes:
        _source_conn: source 数据库的连接 object.
        _target_conn: target 数据库的连接 object.
    """
    _source_conn: object
    _target_conn: object

    def start(self, syn_mode):
        """
        开启该任务的 execution.

        Args:
            syn_mode: 同步模式.
        """
        print(f"Starting the execution of task {self.task_name}")
        is_primary_key = self._is_primary_key(self.target.primary_key)
        is_incre_mode = self._is_incre_mode(syn_mode, is_primary_key)

        source_data = self._pull_source_data(is_incre_mode)

        if is_incre_mode:
            print("Incre mode turns on")
            self._target_conn.update_data(
                source_data,
                self.target.table,
                self.target.fields,
                self.target.primary_key
            )
        else:
            print("Full mode turns on")
            self._target_conn.clear_data(self.target.table)
            self._target_conn.insert_data(
                source_data,
                self.target.table,
                self.target.fields
            )
        
        self._do_after_run_sql()

    def _is_primary_key(self, primary_key):
        """
        判断 target 数据表中指定 key 是否为 primary_key.
        
        Args:
            primary_key: 需要判断的 key.
        """
        return self._target_conn.is_primary_key(
            self.target.table,
            primary_key
        )

    def _is_incre_mode(self, syn_mode, is_primary_key):
        """判断是否满足增量 sync."""
        return syn_mode == SynMode.INCRE.value and is_primary_key

    def _pull_source_data(self, is_incre_mode):
        """根据同步模式进行 data 拉取."""
        if is_incre_mode:
            return self._source_conn.pull_data(
                tb_name=self.source.table,
                tb_fields=self.source.fields,
                filter_key=self.source.filter_key,
                model=self.source.model
            )
        return self._source_conn.pull_data(
            tb_name=self.source.table,
            tb_fields=self.source.fields,
            model=self.source.model
        )
    
    def _do_after_run_sql(self):
        after_run_sql = self.target.after_run_sql
        if after_run_sql:
            update_sql_list = after_run_sql.strip(';').split(';')
            for update_sql in update_sql_list:
                self._target_conn.execute_sql(update_sql)


class TaskFactory():
    """A class used to create a Task obj with specified db conn."""

    def __init__(self, source_conn, target_conn):
        self._source_conn = source_conn
        self._target_conn = target_conn

    def create_task(self, task_json):
        task = dict_to_dataclass(Task, task_json)
        task.config_checksum = calculate_config_checksum(task_json)
        task._source_conn = self._source_conn
        task._target_conn = self._target_conn
        return task