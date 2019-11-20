#!/usr/bin/env python3

import argparse
import json
import mimetypes
import os
import re
import stat
from datetime import datetime
from pathlib import Path

import humanize
from flask import Flask, make_response, request, render_template, send_file, Response
from flask.views import MethodView
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from utils import create_self_signed_cert, generate_password, get_local_ip, get_global_ip

temp_dir = Path(__file__).with_name("temp")
temp_dir.mkdir(exist_ok=True)

secret_key_file = temp_dir / "app_secret_key"
secret_key_file.touch()

app = Flask(__name__, static_url_path='/assets', static_folder='assets')
app.secret_key = secret_key_file.read_text()

if len(app.secret_key) == 0:
    secret_key_file.write_text(generate_password(10))

root = Path("/tmp")
users = {}
auth = HTTPBasicAuth()

ignored = ['.bzr', '$RECYCLE.BIN', '.DAV', '.DS_Store', '.git', '.hg', '.htaccess', '.htpasswd', '.Spotlight-V100',
           '.svn', '__MACOSX', 'ehthumbs.db', 'robots.txt', 'Thumbs.db', 'thumbs.tps']
datatypes = {'audio': 'm4a,mp3,oga,ogg,webma,wav', 'archive': '7z,zip,rar,gz,tar',
             'image': 'gif,ico,jpe,jpeg,jpg,png,svg,webp', 'pdf': 'pdf', 'quicktime': '3g2,3gp,3gp2,3gpp,mov,qt',
             'source': 'atom,bat,bash,c,cmd,coffee,css,hml,js,json,java,less,markdown,md,php,pl,py,rb,rss,sass,scpt,swift,scss,sh,xml,yml,plist',
             'text': 'txt', 'video': 'mp4,m4v,ogv,webm', 'website': 'htm,html,mhtm,mhtml,xhtm,xhtml'}
icontypes = {'fa-music': 'm4a,mp3,oga,ogg,webma,wav', 'fa-archive': '7z,zip,rar,gz,tar',
             'fa-picture-o': 'gif,ico,jpe,jpeg,jpg,png,svg,webp', 'fa-file-text': 'pdf',
             'fa-code': 'atom,plist,bat,bash,c,cmd,coffee,css,hml,js,json,java,less,markdown,md,php,pl,py,rb,rss,sass,scpt,swift,scss,sh,xml,yml',
             'fa-file-text-o': 'txt', 'fa-film': 'mp4,m4v,ogv,webm', 'fa-globe': 'htm,html,mhtm,mhtml,xhtm,xhtml'}


@auth.verify_password
def verify_password(username, password):
    if username in users:
        return check_password_hash(users.get(username), password)
    return False


@app.template_filter('size_fmt')
def size_fmt(size):
    return humanize.naturalsize(size)


@app.template_filter('time_fmt')
def time_desc(timestamp):
    mdate = datetime.fromtimestamp(timestamp)
    str = mdate.strftime('%Y-%m-%d %H:%M:%S')
    return str


@app.template_filter('data_fmt')
def data_fmt(filename):
    t = 'unknown'
    for type, exts in datatypes.items():
        if filename.split('.')[-1] in exts:
            t = type
    return t


@app.template_filter('icon_fmt')
def icon_fmt(filename):
    i = 'fa-file-o'
    for icon, exts in icontypes.items():
        if filename.split('.')[-1] in exts:
            i = icon
    return i


@app.template_filter('humanize')
def time_humanize(timestamp):
    mdate = datetime.utcfromtimestamp(timestamp)
    return humanize.naturaltime(mdate)


def get_type(mode):
    if stat.S_ISDIR(mode) or stat.S_ISLNK(mode):
        type = 'dir'
    else:
        type = 'file'
    return type


def partial_response(path, start, end=None):
    file_size = os.path.getsize(path)

    if end is None:
        end = file_size - start - 1
    end = min(end, file_size - 1)
    length = end - start + 1

    with open(path, 'rb') as fd:
        fd.seek(start)
        bytes = fd.read(length)
    assert len(bytes) == length

    response = Response(
        bytes,
        206,
        mimetype=mimetypes.guess_type(path)[0],
        direct_passthrough=True,
    )
    response.headers.add(
        'Content-Range', 'bytes {0}-{1}/{2}'.format(
            start, end, file_size,
        ),
    )
    response.headers.add(
        'Accept-Ranges', 'bytes'
    )
    return response


def get_range(request):
    range = request.headers.get('Range')
    m = re.match(r'bytes=(?P<start>\d+)-(?P<end>\d+)?', range)
    if m:
        start = m.group('start')
        end = m.group('end')
        start = int(start)
        if end is not None:
            end = int(end)
        return start, end
    else:
        return 0, None


class PathView(MethodView):
    def get(self, p=''):
        hide_dotfile = request.args.get('hide-dotfile', request.cookies.get('hide-dotfile', 'yes'))

        path: Path = root / p
        path = path.resolve().absolute()

        if str(root) not in str(path):
            res = make_response('Not found', 404)
            return res

        if path.is_dir():
            contents = []
            total = {'size': 0, 'dir': 0, 'file': 0}

            for filepath in [Path("../")] + list(path.iterdir()):
                filename = filepath.name

                if filename in ignored:
                    continue
                if filepath.is_file() and hide_dotfile == 'yes' and filename[0] == '.':
                    continue

                stat_res = os.stat(str(filepath))
                info = dict()
                info['name'] = filename
                info['mtime'] = stat_res.st_mtime
                ft = get_type(stat_res.st_mode)
                info['type'] = ft
                total[ft] += 1
                sz = stat_res.st_size
                info['size'] = sz
                total['size'] += sz
                contents.append(info)

            page = render_template('index.html', path=p, contents=contents, total=total, hide_dotfile=hide_dotfile)
            res = make_response(page, 200)
            res.set_cookie('hide-dotfile', hide_dotfile, max_age=16070400)

        elif path.is_file():
            if 'Range' in request.headers:
                start, end = get_range(request)
                res = partial_response(str(path), start, end)
            else:
                res = send_file(str(path))
                res.headers.add('Content-Disposition', 'attachment')
        else:
            res = make_response('Not found', 404)

        return res

    def post(self, p=''):
        path = root / p
        path.mkdir(parents=True, exist_ok=True)

        info = {}
        if path.is_dir():
            files = request.files.getlist('files[]')
            for file in files:
                try:
                    filename = secure_filename(file.filename)
                    file.save(str(path / filename))
                except Exception as e:
                    info['status'] = 'error'
                    info['msg'] = str(e)
                else:
                    info['status'] = 'success'
                    info['msg'] = 'File Saved'
        else:
            info['status'] = 'error'
            info['msg'] = 'Invalid Operation'

        res = make_response(json.JSONEncoder().encode(info), 200)
        res.headers.add('Content-type', 'application/json')

        return res


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="WEB server for file transfer",
                                     formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument("-d", "--dir", type=Path, default=Path().cwd())
    parser.add_argument("--port", type=int, default=60000)
    parser.add_argument("-u", "--user", type=str, default="nano")
    parser.add_argument("-p", "--passwd", type=str, default=generate_password(10))

    args = parser.parse_args()

    path_view = PathView.as_view('path_view')

    path_view_auth = auth.login_required(path_view)
    app.add_url_rule('/', view_func=path_view_auth)

    app.add_url_rule('/<path:p>', view_func=path_view_auth)

    users.update({args.user: generate_password_hash(args.passwd)})

    root = Path(args.dir).resolve().absolute()

    port = str(args.port)

    cert_file = temp_dir / "cert_file.crt"
    key_file = temp_dir / "key_file.key"
    create_self_signed_cert(cert_file, key_file)

    print("\n\n")
    print(f"Local address: https://{get_local_ip()}:{args.port}")
    print(f"Global address: https://{get_global_ip()}:{args.port}")

    print(f"User: {args.user}")
    print(f"Password: {args.passwd}")
    print("\n")

    app.run(host=get_local_ip(),
            port=port,
            threaded=True,
            debug=False,
            ssl_context=(str(cert_file), str(key_file)))
