import marimo

__generated_with = "0.18.4"
app = marimo.App(
    width="full",
    layout_file="layouts/konflux-cache-time-via-tasks.grid.json",
)

with app.setup:
    # Initialization code that runs before all other cells
    import marimo as mo
    import webbrowser
    import requests
    import threading
    from http.server import HTTPServer, BaseHTTPRequestHandler
    from urllib.parse import urlparse, parse_qs, urlencode
    import secrets
    import hashlib
    import base64
    import re
    from kubernetes import client
    from datetime import datetime
    import pyarrow as pa
    import altair as alt


@app.cell
def _():
    mo.md(r"""
    # Library functions
    """)
    return


@app.cell
def _():
    mo.md(r"""
    ## Cluster connectivity
    """)
    return


@app.cell
def _():
    def generate_pkce_pair():
        # 1. Create a high-entropy verifier
        verifier = secrets.token_urlsafe(64)

        # 2. Hash it with SHA256
        sha256_hash = hashlib.sha256(verifier.encode('utf-8')).digest()

        # 3. Base64-URL encode the hash (remove padding and replace chars)
        challenge = base64.urlsafe_b64encode(sha256_hash).decode('utf-8').rstrip('=')

        return verifier, challenge

    def get_ocp_token(cluster_api, tls_verify=True):
        # 1. Initialize server on port 0 (OS picks an unused port)
        # We use a simple list or object to store the code since the handler 
        # is instantiated per request
        auth_context = {"code": None}

        class OAuthCallbackHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                query = urlparse(self.path).query
                params = parse_qs(query)
                if "code" in params:
                    auth_context["code"] = params["code"][0]
                    self.send_response(200)
                    self.send_header("Content-type", "text/html")
                    self.end_headers()
                    html = """
                    <!DOCTYPE html>
                    <html>
                    <body style="text-align: center; font-family: sans-serif; padding-top: 50px;">
                        <h1>Authenticated successfully!</h1>
                        <p>This window will close automatically. If it doesn't, you can safely close it manually.</p>
                        <script type="text/javascript">
                            // Short delay to ensure the user sees the success message
                            setTimeout(function() {
                                window.open('', '_self', ''); 
                                window.close();
                            }, 1000);
                        </script>
                    </body>
                    </html>
                    """
                    self.wfile.write(html.encode("utf-8"))
                else:
                    self.send_response(400)
                    self.end_headers()

            def log_message(self, format, *args): return

        # 2. Create the server and extract the assigned port
        server = HTTPServer(('127.0.0.1', 0), OAuthCallbackHandler)
        actual_port = server.server_port
        redirect_uri = f"http://127.0.0.1:{actual_port}/callback"

        # 3. Start background listener
        thread = threading.Thread(target=server.handle_request)
        thread.start()

        # 4. Fetch discovery info and open browser

        # Generate PKCE credentials
        code_verifier, code_challenge = generate_pkce_pair()

        # Get authorization endpoint
        meta_url = f"{cluster_api}/.well-known/oauth-authorization-server"
        md_resp = requests.get(meta_url, verify=tls_verify)
        md_resp.raise_for_status()
        metadata = md_resp.json()
        auth_endpoint = metadata['authorization_endpoint']
        token_endpoint = metadata["token_endpoint"]

        auth_params = {
            "client_id": "openshift-cli-client",
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "scope": "user:full"
        }        

        encoded_params = urlencode(auth_params)
        auth_url = f"{auth_endpoint}?{encoded_params}"

        webbrowser.open(auth_url)

        # Wait for the user to finish
        thread.join(timeout=60) # Set a timeout so it doesn't hang forever
        server.server_close()

        if not auth_context["code"]:
            raise Exception("Failed to get auth code from oAuth exchange")

        # 5. Exchange code for token
        token_payload = {
            "grant_type": "authorization_code",
            "code": auth_context["code"], # The code from the redirect
            "redirect_uri": redirect_uri,
            "client_id": "openshift-cli-client",
            "client_secret": "",
            "code_verifier": code_verifier # CRITICAL: The raw verifier string
        }            
        token_resp = requests.post(token_endpoint, data=token_payload, verify=tls_verify)

        if not token_resp.ok:
            # This will tell us if it's "invalid_grant" (bad code/verifier) 
            # or "redirect_uri_mismatch"
            print(f"Error Details: {token_resp.text}")

        token_resp.raise_for_status()
        return token_resp.json().get("access_token")

    def get_k8s_api(cluster_api, token, tls_verify=True):
        configuration = client.Configuration()
        configuration.host = cluster_api
        configuration.verify_ssl = tls_verify
        configuration.api_key = {"authorization": f"Bearer {token}"}

        return client.CoreV1Api(client.ApiClient(configuration))

    def is_token_valid(cluster_api, token, tls_verify=True):
        """Checks if the token is valid by calling the 'whoami' endpoint."""
        if not token:
            return False
        try:
            # OpenShift 'whoami' equivalent
            url = f"{cluster_api}/apis/user.openshift.io/v1/users/~"
            headers = {"Authorization": f"Bearer {token}"}
            response = requests.get(url, headers=headers, verify=tls_verify, timeout=5)
            return response.status_code == 200
        except Exception:
            return False
    return get_k8s_api, get_ocp_token, is_token_valid


@app.cell
def _():
    mo.md(r"""
    ## KubeArchive connectivity
    """)
    return


@app.cell
def _(cluster):
    def get_cluster_archive_url(cluster_api_url):
        parsed = urlparse(cluster_api_url)
        hostname = parsed.hostname

        if hostname and hostname.startswith("api."):
            new_hostname = hostname.replace("api.", "kubearchive-api-server-product-kubearchive.apps.", 1)
        else:
            new_hostname = f"kubearchive-api-server-product-kubearchive.apps.{hostname}"

        return f"https://{new_hostname}"

    archive_url = get_cluster_archive_url(cluster)
    archive_url
    return (archive_url,)


@app.cell
def _():
    mo.md(r"""
    ## General K8s item analysis
    """)
    return


@app.function
def summarize_k8s_items(items):
    _count = 0
    _kinds = set()
    _min_ts = None
    _max_ts = None
    _oldest_name = None
    _newest_name = None
    _labels = set()

    for _item in items:
        _count += 1
        _kind = _item.get("kind")
        if _kind:
            _kinds.add(_kind)

        _metadata = _item.get("metadata", {})
        _name = _metadata.get("name")
        _ts_str = _metadata.get("creationTimestamp")

        if _ts_str:
            # Handle 'Z' suffix for UTC which might not be handled by older fromisoformat versions
            if _ts_str.endswith('Z'):
                _ts_str = _ts_str[:-1] + '+00:00'

            try:
                _dt = datetime.fromisoformat(_ts_str)

                if _min_ts is None or _dt < _min_ts:
                    _min_ts = _dt
                    _oldest_name = _name

                if _max_ts is None or _dt > _max_ts:
                    _max_ts = _dt
                    _newest_name = _name
            except ValueError:
                pass

        _labels |= _metadata.get("labels", {}).keys()

    return {
        "count": _count,
        "oldest": _min_ts,
        "newest": _max_ts,
        "oldest_name": _oldest_name,
        "newest_name": _newest_name,
        "kinds": frozenset(_kinds),
        "labels": frozenset(_labels),
    }


@app.function
def k8s_item_label_matrix(items):
    _names = []
    _item_labels_list = []
    _seen_keys = set()

    # Iterate through items to collect names and labels
    for _item in items:
        _meta = _item.get("metadata", {})
        _names.append(_meta.get("name"))

        # Ensure labels is a dict, even if None
        _labels = _meta.get("labels") or {}
        _item_labels_list.append(_labels)
        _seen_keys.update(_labels.keys())

    # Initialize data dictionary with the name column
    _data = {"name": _names}

    # Populate columns for each unique label found
    for _key in sorted(_seen_keys):
        _data[_key] = [_labels.get(_key) for _labels in _item_labels_list]

    return pa.Table.from_pydict(_data)


@app.function
def k8s_item_matrix(items):
    field_map = {
        'apiVersion': 'apiVersion',
        'kind': 'kind',
        'namespace': 'metadata.namespace',
        'name': 'metadata.name',
        'creationTime': 'metadata.creationTimestamp',
        'labels': 'metadata.labels',
        'metadata': 'metadata',
        'spec': 'spec',
        #'status': 'status',
    }
    data = {}
    for item in items:
        for field, res_field in field_map.items():
            res_field_parent = item
            res_field_parts = res_field.split('.')
            for part in res_field_parts[:-1]:
                res_field_parent = res_field_parent.get(part, {})
            value = res_field_parent.get(res_field_parts[-1])

            if field.endswith('Time'):
                value = datetime.fromisoformat(value)

            data_value_list = data.setdefault(field, [])
            data_value_list.append(value)

    return data


@app.cell
def _():
    mo.md(r"""
    ## Looking at TaskRuns
    """)
    return


@app.function
def get_taskruns(api, namespace, label_selector=None):
    custom_api = client.CustomObjectsApi(api.api_client)
    group = "tekton.dev"
    version = "v1"
    plural = "taskruns"
    limit = 100

    try:
        # Try fetching v1 PipelineRuns
        taskruns = custom_api.list_namespaced_custom_object(
            group, version, namespace, plural, limit=limit, label_selector=label_selector
        )
    except client.exceptions.ApiException as _e:
        if _e.status == 404:
            # Fallback to v1beta1 if v1 is not available on the cluster
            version = "v1beta1"
            taskruns = custom_api.list_namespaced_custom_object(
                group, version, namespace, plural, limit=limit, label_selector=label_selector
            )
        else:
            raise _e

    while True:
        for item in taskruns.get("items", []):
            yield item
        if cont_key := taskruns.get("metadata", {}).get("continue"):
            taskruns = custom_api.list_namespaced_custom_object(
                group, version, namespace, plural, limit=limit, label_selector=label_selector, _continue=cont_key
            )
        else:
            break

    return taskruns


@app.function
def tr_time_rec(plr):
    metadata = plr.get("metadata", {})
    status = plr.get("status", {})
    labels = metadata.get("labels", {})
    data = {
        "namespace": metadata.get("namespace"),
        "name": metadata.get("name"),
        "type": labels.get("pipelines.appstudio.openshift.io/type"),
        "application": labels.get("appstudio.openshift.io/application"),
        "component": labels.get("appstudio.openshift.io/component"),
        "repository": labels.get("pipelinesascode.tekton.dev/repository"),
        "event-type": labels.get("pipelinesascode.tekton.dev/event-type"),
        "pull-request": labels.get("pipelinesascode.tekton.dev/pull-request"),
        "pipelineRun": labels.get("tekton.dev/pipelineRun"),
        "task": labels.get("tekton.dev/task"),
        "pipelineTask": labels.get("tekton.dev/pipelineTask"),
    }

    time_fields = [
        (metadata, "creationTimestamp"),
        (status, "startTime"),
        (status, "completionTime"),                
        (metadata, "deletionTimestamp"),
    ]
    for obj, field in time_fields:
        data[field] = (t := obj.get(field)) and datetime.fromisoformat(t)

    duration_fields = [
        ("runTime", "startTime", "completionTime"),
        ("totalWait", "creationTimestamp", "completionTime"),
    ]
    for duration_field, start_field, stop_field in duration_fields:
        data[duration_field] = (s := data.get(start_field)) and (e := data.get(stop_field)) and (e - s).total_seconds()

    return data


@app.function
def trs_time_table(trs):
    return pa.Table.from_pylist([tr_time_rec(tr) for tr in trs])


@app.function
def plrs_runtime_chart(time_table):
    # replace _df with your data source
    chart = (
        alt.Chart(time_table)
        .mark_bar()
        .encode(
            x=alt.X(field='runTime', type='quantitative', bin=True),
            y=alt.Y(aggregate='count', type='quantitative'),
            tooltip=[
                alt.Tooltip(field='runTime', format=',.2f', bin=True),
                alt.Tooltip(aggregate='count')
            ]
        )
        .properties(
            height=290,
            width='container',
            config={
                'axis': {
                    'grid': False
                }
            }
        )
    )
    return chart


@app.cell
def _():
    mo.md(r"""
    # Build caching timing experiment
    """)
    return


@app.cell
def _():
    mo.md(r"""
    ## Connect to cluster & archive
    """)
    return


@app.cell
def _():
    cluster = "https://api.stone-stg-rh01.l2vh.p1.openshiftapps.com:6443"
    namespace = "konflux-samples-tenant"
    return (cluster,)


@app.cell
def _(cluster, get_k8s_api, get_ocp_token, is_token_valid):
    token = get_ocp_token(cluster)
    api = get_k8s_api(cluster, token)
    is_token_valid(cluster, token)
    return (token,)


@app.cell
def _(archive_url, get_k8s_api, token):
    archive_api = get_k8s_api(archive_url, token)
    archive_api.list_namespace()
    return (archive_api,)


@app.cell
def _():
    mo.md(r"""
    ## Get the PLRS we care about
    """)
    return


@app.function
def get_pr_build_trs(api, pr_id):
    namespace="konflux-samples-tenant"
    tr_labels = ','.join([
        "pipelines.appstudio.openshift.io/type=build",
        "appstudio.openshift.io/application=prjctl-tst-main",
        "appstudio.openshift.io/component=prjctl-tst-cmp1-main",
        "pipelinesascode.tekton.dev/event-type in (pull_request,retest-all-comment)",
        f"pipelinesascode.tekton.dev/pull-request={pr_id}",
        "tekton.dev/pipelineTask=build-container"
#        "pipelinesascode.tekton.dev/state=completed",
    ])
    trs = get_taskruns(api, namespace, label_selector=tr_labels)
    trs = list(trs)
    return trs


@app.cell
def _():
    mo.md(r"""
    ## No-cache PLRs (PR 80)
    """)
    return


@app.cell
def _(archive_api):
    _pr_number = 80
    _trs = get_pr_build_trs(archive_api, _pr_number)
    tt = trs_time_table(_trs)
    return (tt,)


@app.cell
def _(tt):
    tt
    return


@app.cell
def _(tt):
    plrs_runtime_chart(tt)
    return


@app.cell
def _():
    mo.md(r"""
    ## Cached PLRs (PR 81)
    """)
    return


@app.cell
def _(archive_api):
    _cached_pr_number = 81
    _cached_plrs = get_pr_build_trs(archive_api, _cached_pr_number)
    cached_tt = trs_time_table(_cached_plrs)
    return (cached_tt,)


@app.cell
def _(cached_tt):
    cached_tt
    return


@app.cell
def _(cached_tt):
    plrs_runtime_chart(cached_tt)
    return


@app.cell(hide_code=True)
def _():
    mo.md(r"""
    ## Comparison
    """)
    return


@app.cell
def _(cached_tt, tt):
    import pandas as pd

    # Helper to ensure input is an Arrow Table
    def _ensure_arrow(data):
        if isinstance(data, pa.Table):
            return data
        if hasattr(data, "to_arrow"):
            return data.to_arrow()
        # Fallback: convert from pandas-like object
        return pa.Table.from_pandas(pd.DataFrame(data) if not isinstance(data, pd.DataFrame) else data)

    # Load and label data
    _t_tt = _ensure_arrow(tt).append_column("Condition", pa.array(["No Cache (PR 80)"] * len(tt)))
    _t_cached = _ensure_arrow(cached_tt).append_column("Condition", pa.array(["Cached (PR 81)"] * len(cached_tt)))

    # Combine datasets
    _combined = pa.concat_tables([_t_tt, _t_cached])

    # Calculate IQR for outlier removal based on the combined dataset
    _run_times = _combined['runTime']
    _quantiles = pa.compute.quantile(_run_times, q=[0.25, 0.75])
    _q1 = _quantiles[0].as_py()
    _q3 = _quantiles[1].as_py()
    _iqr = _q3 - _q1
    _lower = _q1 - 1.5 * _iqr
    _upper = _q3 + 1.5 * _iqr

    # Filter outliers
    _mask = pa.compute.and_(
        pa.compute.greater_equal(_run_times, _lower),
        pa.compute.less_equal(_run_times, _upper)
    )
    _filtered = _combined.filter(_mask)

    # Calculate means for the vertical lines
    _mean_tt = pa.compute.mean(_filtered.filter(pa.compute.equal(_filtered['Condition'], "No Cache (PR 80)"))['runTime']).as_py()
    _mean_cached = pa.compute.mean(_filtered.filter(pa.compute.equal(_filtered['Condition'], "Cached (PR 81)"))['runTime']).as_py()

    _means_df = pd.DataFrame([
        {'Condition': "No Cache (PR 80)", 'mean_runTime': _mean_tt},
        {'Condition': "Cached (PR 81)", 'mean_runTime': _mean_cached}
    ])

    # Create the chart
    _base = alt.Chart(_filtered.to_pandas())

    # Line histogram (Frequency Polygon)
    _lines = _base.mark_line(interpolate='monotone').encode(
        x=alt.X('runTime:Q', bin=alt.Bin(maxbins=20), title='Run Time (seconds)'),
        y=alt.Y('count()', title='Frequency'),
        color='Condition:N',
        tooltip=['Condition', 'count()', alt.Tooltip('runTime', bin=True)]
    )

    # Vertical mean lines
    _rules = alt.Chart(_means_df).mark_rule(strokeDash=[4, 4], size=2).encode(
        x='mean_runTime:Q',
        color='Condition:N',
        tooltip=['Condition', alt.Tooltip('mean_runTime', format='.2f')]
    )

    (_lines + _rules).properties(
        title='Run Time Distribution (Outliers Removed) with Means',
        width=500,
        height=350
    ).interactive()
    return


if __name__ == "__main__":
    app.run()
