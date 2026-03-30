import json

def prepare(request : bytes, collection_hash: str):

    request = json.loads(request.decode("utf-8"))
    print(request.get('modules')['event_logs'])
    return {
        "data": request,
        "collection_hash": collection_hash
    }