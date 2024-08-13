import sys
import yaml
import requests
import json
from typing import List, Dict, Tuple, Optional, Any

def parse_swagger(file_path: str):
    try:
        with open(file_path, 'r') as file:
            return yaml.safe_load(file)
    except yaml.YAMLError as e:
        print(f"Error parsing YAML file: {e}")
        sys.exit(1)
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        sys.exit(1)

def perform_http_request(http_request: Dict[str, any], hhi_payload: Optional[str] = None):
    headers = {}
    if hhi_payload:
        headers = {'Host': hhi_payload}
    try:
        response = requests.request(
            method=http_request['method'],
            url=http_request['url'],
            params=http_request['query'],
            json=http_request['json_body'] or None,
            data=http_request['form_body'] or None,
            headers=headers,
            timeout=10
        )
        return response.status_code, response.text
    except requests.RequestException as e:
        return 0, str(e)

def parse_swagger_parameters(method_info: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """
    Parse parameters from a Swagger/OpenAPI path method definition.
    
    Args:
        method_info (Dict[str, Any]): The method information from a Swagger path.
    
    Returns:
        Dict[str, Dict[str, Any]]: A dictionary containing 'query', 'json_body', and 'form_body' parameters.

    """

    result = {
        'query': {},
        'json_body': {},
        'form_body': {}
    }

    def extract_example(item: Dict[str, Any]) -> Any:
        return item.get('example', f"<{item.get('type', 'any')}>")

    # Parse query parameters
    for param in method_info.get('parameters', []):
        if param['in'] == 'query':
            name = param['name']
            result['query'][name] = extract_example(param.get('schema', param))

    # Parse request body
    if 'requestBody' in method_info:
        content = method_info['requestBody'].get('content', {})
        for content_type, content_schema in content.items():
            body_type = 'json_body' if 'json' in content_type else 'form_body'
            schema = content_schema.get('schema', {})
            properties = schema.get('properties', {})
            
            for prop_name, prop_info in properties.items():
                result[body_type][prop_name] = extract_example(prop_info)
            
            # If there's an example, use it to override or fill in missing values
            if 'example' in content_schema:
                result[body_type].update(content_schema['example'])
            elif 'examples' in content_schema:
                first_example = next(iter(content_schema['examples'].values()))
                if 'value' in first_example:
                    result[body_type].update(first_example['value'])

    return result

def get_apis(file_path: str):
    """
    Args:
        file_path: str: The file path for swagger.yml file.
    
    Returns:
        List[Dict[str, any]]: A List of dictionary containing all 'url', 'method', 'query', 'json_body', and form_body
    
    Examples:

    request_params output
    {'url': 'http://localhost:8000/api/sqlinovuln', 'method': 'get', 'query': {}, 'json_body': {}, 'form_body': {}}
    {'url': 'http://localhost:8000/api/sqlivuln', 'method': 'post', 'query': {}, 'json_body': {'password': 'testing', 'username': 'testing'}, 'form_body': {}}
    
    """
    apis_data = parse_swagger(file_path)
    urls = []
    urls = apis_data.get('servers')
    # api_requests
    # url, method, json_body, query_params, form_data
    api_requests = []
    http_requests = []
    for url in urls:
        paths = {}
        paths = apis_data.get('paths')
        for path in paths:
            for method in paths[path]:
                query_params = {'query': {}}
                body_params = {'json_body': {}, 'form_body': {}}
                request_params = {'query': {}, 'json_body': {}, 'form_body': {}}
                if 'requestBody' in paths[path][method]:
                    # if content type application/www-urlencoded / application/json
                    body_schema = paths[path][method]['requestBody']['content']
                    # how many properties and its default input?
                    body_params = parse_swagger_parameters(paths[path][method])

                elif 'parameters' in paths[path][method]:
                    query_params = parse_swagger_parameters(paths[path][method])

                else:
                    # no parameters
                    pass
                
                # combine all dicts
                request_params = {
                    'url': f"{url['url']}{path}",
                    'method': method,
                    'query': query_params['query'],
                    'json_body': body_params['json_body'],
                    'form_body': body_params['form_body']
                }
                http_requests.append(request_params)
    return http_requests

