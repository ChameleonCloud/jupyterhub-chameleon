from urllib.parse import parse_qsl


def get_import_params(query):
    """Given an HTML query string, find the parameters relevant for import.

    :type query: Union[dict,str]
    :param query: the request query parameters (as a query string, or as a
                  parsed dictionary)
    :returns: a tuple of the import source and path, if both were on the
              querystring, None otherwise
    """
    if isinstance(query, str):
        query = dict(parse_qsl(query))

    src = query.get('source')
    src_path = query.get('src_path')

    if src is not None and src_path is not None:
        return (src, src_path)
    else:
        return None
