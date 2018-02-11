"""
smart_client.py
Author: AJ Po-Deziel
January 25th, 2018

This program analyzes a given web page and its supported technologies.
Additionally, the list of cookies present on the page is also returned.
"""


import io
import re
import socket
import ssl
import sys
import traceback


# HTTP Status Codes
HTTP_SWITCHING_PROTOCOLS = '101'
HTTP_OK = '200'
HTTP_NOT_FOUND = '404'
HTTP_REDIRECT = ['300', '301', '302', '303', '304', '305', '306', '307']
HTTP_VERSION_NOT_SUPPORTED = '505'

# HTTP Versions
HTTP_VERSION_LIST = ['HTTP/2.0', 'HTTP/1.1', 'HTTP/1.0']


class CookieItem:
    def __init__(self, name, key, domain):
        """
        Data structure for cookies found in HTTP header.

        :param name: Name of cookie, if exists.
        :param key: Key of cookie, if exists.
        :param domain: Domain that cookie belongs to, if exists.
        """

        self.name = name
        self.key = key
        self.domain = domain


def request_socket(address, http_version):
    """
    Perform HEAD request to web server over standard socket.

    :param address: Web address passed from stdin.
    :param http_version: HTTP version to pass in request.
    :return: Decoded response from web server.
    """

    request = io.StringIO()

    if http_version == 'HTTP/2.0':
        request_str = "HEAD / HTTP/1.1\r\nHost: {0}\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\n" \
                      "HTTP2-Settings:\r\n\r\n".format(address)

    else:
        request_str = "HEAD / {0}\r\nHost: {1}\r\nUser-Agent: thing\r\n\r\n".format(http_version, address)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((address, 80))

    request.write(request_str)
    stream_request = request.getvalue().encode("UTF-8")

    # Attempt to send stream_request via SSL socket to web server
    try:
        s.send(stream_request)
    except:
        traceback.print_exc()

    response = s.recv(4096)  # 4 KB allocated for response
    s.close()

    return response.decode("UTF-8")


def request_ssl_socket(address, http_version):
    """
    Perform HEAD request to web server over SSL wrapped socket.

    :param address: Web address passed from stdin.
    :param http_version: HTTP version to pass in request.
    :return: Decoded response from web server.
    """

    request = io.StringIO()

    if http_version == 'HTTP/2.0':
        result_http2 = check_version_http2(address)

        if result_http2 == 'HTTP/2.0':
            return True

    ssl_socket = ssl.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    ssl_socket.connect((address, 443))

    request_str = "HEAD / {0}\r\nHost: {1}\r\nUser-Agent: thing\r\n\r\n".format(http_version, address)

    request.write(request_str)
    stream_request = request.getvalue().encode("UTF-8")

    # Attempt to send stream_request via SSL socket to web server
    try:
        ssl_socket.send(stream_request)
    except:
        traceback.print_exc()

    response = ssl_socket.recv(4096)  # 4 KB allocated for response
    ssl_socket.close()

    return response.decode("UTF-8")


def check_version_http2(address):
    """
    Check if HTTP/2.0 is supported on web server.

    :param address: Web address passed from stdin.
    :return: HTTP/2.0 if supported. Otherwise, None.
    """
    request_str = io.StringIO()

    request_str_cleartext = "HEAD / HTTP/1.1\r\nHost: {0}\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\n" \
                            "HTTP2-Settings:\r\n\r\n".format(address)

    # Check for clear text upgrade
    request_str.write(request_str_cleartext)
    stream_request = request_str.getvalue().encode("UTF-8")
    socket_http2 = ssl.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    socket_http2.connect((address, 443))

    try:
        socket_http2.send(stream_request)
    except:
        traceback.print_exc()

    response = socket_http2.recv(4096)
    socket_http2.close()

    resp = response.decode("UTF-8")
    resp_list = resp.split(" ")
    resp_status_code = resp_list[1]

    # If Switching Protocols status code is encountered, return. Otherwise, continue.
    if resp_status_code == HTTP_SWITCHING_PROTOCOLS:
        return 'HTTP/2.0'

    # Negotiate connection to HTTP/2.0 via TLS
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    socket_npn = ssl_context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    ssl_context.set_npn_protocols(['h2', 'http/1.1'])
    socket_npn.connect((address, 443))

    result = socket_npn.selected_npn_protocol()

    # h2 encounter means HTTP/2.0 is supported. Otherwise, return None.
    if result == 'h2':
        resp_version = 'HTTP/2.0'
        return resp_version
    else:
        return None


def detect_https(address):
    """
    Determine if web server/site supports HTTPS.

    :param address: Web address passed from stdin.
    :return: True/False
    """

    # Perform request to server with SSL wrapped socket
    resp = request_ssl_socket(address, 'HTTP/1.1')

    # Separate string by single whitespace and place into list
    resp_list = resp.split(" ")

    # Determine if response code is a redirect code.
    # If yes, investigate redirect location.
    # Otherwise, return True.
    resp_status_code = resp_list[1]
    if resp_status_code in HTTP_REDIRECT:
        redirect_resp = resp.splitlines()
        redirect_resp_location = [x for x in redirect_resp if x.startswith('Location')]

        # If redirect location provided is to an HTTPS address, web server supports HTTPS
        # Otherwise, it must not support HTTPS.
        if 'Location: https://' in redirect_resp_location[0]:
            return True
        else:
            return False
    else:
        return True


def verify_http_version(address, https):
    """
    Determine the newest HTTP version supported by the web server.

    :param address: Web address passed from stdin
    :param https: Result from detect_https if web server supports HTTPS
    :return: Newest version of HTTP supported by web server
    """

    for version in HTTP_VERSION_LIST:
        # Perform request to server with address and version and parse response

        # Case 1: HTTP/2.0
        if version == 'HTTP/2.0':
            if https is True:
                resp_http2 = request_ssl_socket(address, version)
            else:
                resp_http2_std = request_socket(address, version)
                resp_list = resp_http2_std.split(' ')
                resp_status_code = resp_list[1]

                # Switching Protocols status code encounter means HTTP/2.0 is supported.
                if resp_status_code == HTTP_SWITCHING_PROTOCOLS:
                    resp_http2 = True
                else:
                    resp_http2 = False

            # Verify result from server response
            if resp_http2 is True:
                http_version = 'HTTP/2.0'
                break
            else:
                continue

        else:
            # Verify HTTP/1.1 and HTTP/1.0
            if https is True:
                resp = request_ssl_socket(address, version)
            else:
                resp = request_socket(address, version)

            resp_list = resp.split(' ')
            resp_version = resp_list[0]
            resp_status_code = resp_list[1]

            # Case 2: HTTP version match
            if resp_version == version:
                http_version = resp_version
                break

            # Case 3: Version is not supported
            elif resp_status_code == HTTP_VERSION_NOT_SUPPORTED:
                continue

            # Case 4: All other cases, continue through HTTP_VERSION_LIST.
            else:
                continue

    return http_version


def find_cookies(address, https, http_version):
    """
    Retrieve cookies from web server.

    :param address: Web address passed from stdin.
    :param https: Result from detect_https if web server supports HTTPS
    :param http_version: Newest HTTP version supported by web server
    :return: List of cookies
    """
    # If newest version supported is HTTP/2.0, force HTTP/1.1 request on web server
    if http_version == 'HTTP/2.0':
        if https is True:
            resp = request_ssl_socket(address, 'HTTP/1.1')
        else:
            resp = request_socket(address, 'HTTP/1.1')
    else:
        if https is True:
            resp = request_ssl_socket(address, http_version)
        else:
            resp = request_socket(address, http_version)

    # Parse response for cookies
    resp_list = resp.splitlines()
    resp_list_cookies = [x for x in resp_list if x.startswith('Set-Cookie')]

    # Parse resp_list_cookies to get each respective cookie out, format as (name, key, domain_name)
    cookies_list = []

    for cookie in resp_list_cookies:
        cookies = cookie.split('; ')
        cookies_list.append(cookies)

    cookies_strip_list = []

    for cookie in cookies_list:
        cookie[0] = cookie[0].replace('Set-Cookie: ', '')
        cookies_strip_list.append(cookie)

    parsed_cookies = []

    # Parse each cookie for name, key, and domain.
    # Once done, pass into CookieItem and append to parsed_cookies.
    for cookie in cookies_strip_list:

        cookie_name = '-'
        cookie_key = '-'
        cookie_domain = '-'

        # Find cookie's key, if exists
        if cookie[0] is not None:
            pattern = re.match('(.+?)(?=\=)', cookie[0])
            cookie_key = pattern.group(0)
        elif cookie[0] is None:
            cookie_key = '-'

        for cookie_item in cookie[1:]:
            # Find name of cookie, if exists
            if 'name' in cookie_item:
                pattern = re.search('=(.+)', cookie_item)
                cookie_name = pattern.group(1)
                continue
            # Find domain belonging to cookie, if exists
            elif 'domain' in cookie_item:
                pattern = re.search('=(.+)', cookie_item)
                cookie_domain = pattern.group(1)
                continue
            else:
                continue

        parsed_cookies.append(CookieItem(cookie_name, cookie_key, cookie_domain))

    return parsed_cookies


def main():
    # Verify argument length is valid
    if len(sys.argv) > 2:
        raise Exception('Invalid argument length. Only 1 web address allowed at a time.')
        sys.exit()

    if len(sys.argv) < 2:
        raise Exception('Invalid argument length. Please enter a web address.')
        sys.exit()

    print('Performing URL retrival... ', end='')
    url_input = sys.argv[1]
    print('\t\t\tDONE.')

    print('Verifying HTTPS support... ', end='')
    # Task 1: Verify HTTPS support on web server
    https_status = detect_https(url_input)
    if https_status is True:
        https_support = 'Yes'
        print('\t\t\tDONE.')
    else:
        https_support = 'No'
        print('\t\t\tDONE.')

    print('Verifying newest HTTP version supported... ', end='')
    # Task 2: Determine newest HTTP version
    http_version = verify_http_version(url_input, https_status)
    print('\tDONE.')

    print('Retrieving cookies... ', end='')
    # Task 3: Find all cookies at address
    cookies = find_cookies(url_input, https_status, http_version)
    print('\t\t\t\tDONE.\n\n')

    # Output to terminal results of methods executed per assignment spec
    # Print website name
    print('Website: ' + url_input)

    # 1. Return if HTTPS supported or not
    print('1. Support of HTTPS: ' + https_support)

    # 2. Get newest HTTP version supported by web server
    print('2. The newest HTTP version that the web server supports: ' + http_version)

    # 3. List all cookies
    print('3. List of cookies: ', end='')

    if not cookies:
        print('No Set-Cookie attributes found in HTTP header.')
    else:
        print('\r')

    for item in cookies:
        cookie_item = 'name: {0}, key: {1}, domain name: {2}'.format(item.name, item.key, item.domain)
        print(cookie_item)


if __name__ == '__main__':
    main()
