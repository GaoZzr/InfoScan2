# 记录日志的模块

from loguru import logger
import pathlib
import sys
import os

# 终端日志输出格式
stdout_fmt = '<cyan>{time:HH:mm:ss,SSS}</cyan> ' \
                 '[<level>{level: <5}</level>] ' \
                 '<blue>{module}</blue>:<cyan>{line}</cyan> - ' \
                 '<level>{message}</level>'
# 日志文件记录格式
logfile_fmt = '<light-green>{time:YYYY-MM-DD HH:mm:ss,SSS}</light-green> ' \
                  '[<level>{level: <5}</level>] ' \
                  '<cyan>{process.name}({process.id})</cyan>:' \
                  '<cyan>{thread.name: <10}({thread.id: <5})</cyan> | ' \
                  '<blue>{module}</blue>.<blue>{function}</blue>:' \
                  '<blue>{line}</blue> - <level>{message}</level>'

log_path = pathlib.Path(__file__).parent.resolve().joinpath('logs')
if not log_path.is_dir():
    log_path.mkdir()
log_path = log_path.joinpath('log.log').resolve()


logger.remove()
logger.level(name='TRACE', no=5, color='<cyan><bold>', icon='✏️')
logger.level(name='DEBUG', no=10, color='<blue><bold>', icon='🐞 ')
logger.level(name='INFOR', no=20, color='<green><bold>', icon='ℹ️')
logger.level(name='ALERT', no=30, color='<white><bold>', icon='⚠️')
logger.level(name='ERROR', no=40, color='<red><bold>', icon='❌️')
logger.level(name='FATAL', no=50, color='<RED><bold>', icon='☠️')
if not os.environ.get('PYTHONIOENCODING'):  # 设置编码
    os.environ['PYTHONIOENCODING'] = 'utf-8'
logger.add(sys.stderr, level='INFOR', format=stdout_fmt, enqueue=True)
logger.add(log_path, level='DEBUG', format=logfile_fmt, enqueue=True, encoding='utf-8')