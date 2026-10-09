def csrf_token() -> str:
    token = session.get('_csrf_token')
    if not token:
        token = secrets.token_urlsafe(32)
        session['_csrf_token'] = token
    return token

def role_required(required_role: str):
    if required_role not in ROLE_LEVELS:
        raise ValueError(f'Unsupported role: {required_role}')

    def decorator(view):

        @wraps(view)
        def wrapped(*args, **kwargs):
            user = getattr(g, 'user', None)
            if user is None:
                if request.path.startswith('/api/'):
                    return (jsonify({'error': 'Authentication required.'}), 401)
                return redirect(url_for('login_page', next=request.full_path))
            if ROLE_LEVELS.get(user['role'], 0) < ROLE_LEVELS[required_role]:
                if request.path.startswith('/api/'):
                    return (jsonify({'error': 'Insufficient account permission.'}), 403)
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator

@app.before_request
def load_account_and_protect_routes():
    g.user = None
    user_id = session.get('user_id')
    if user_id is not None:
        user = get_db().execute('\n            SELECT id, username, role, is_active, created_at, last_login_at\n            FROM users\n            WHERE id = ?\n            ', (user_id,)).fetchone()
        if user is not None and user['is_active']:
            g.user = user
        else:
            session.clear()
    if request.method in {'POST', 'PUT', 'PATCH', 'DELETE'}:
        expected = session.get('_csrf_token', '')
        supplied = request.headers.get('X-CSRF-Token', '') or request.form.get('csrf_token', '')
        if not expected or not supplied or (not hmac.compare_digest(expected, supplied)):
            if request.path.startswith('/api/'):
                return (jsonify({'error': 'Invalid or missing CSRF token.'}), 400)
            abort(400)
    if request.endpoint not in PUBLIC_ENDPOINTS and g.user is None:
        if request.path.startswith('/api/'):
            return (jsonify({'error': 'Authentication required.'}), 401)
        return redirect(url_for('login_page', next=request.full_path if request.query_string else request.path))
