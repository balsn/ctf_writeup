#!/usr/bin/env python3
# Python 3.6.5
import sys
import re
import argparse

def main(argv):
    with open(argv.filename, 'r+') as f:
        origin_html = f.read()
        html = generateSideBar(origin_html)
        f.seek(0)
        f.write(html)
        f.truncate() #https://stackoverflow.com/questions/2424000/read-and-overwrite-a-file-in-python

def generateSideBar(html):
    lines = html.split('\n')
    chals = {}
    for line in lines:
        if '<a class="header-link" href="#' in line:
            if '<h2 id="' in line:
                chal_type = re.findall('<h2 id="(.*?)">', line)[0]
                chals[chal_type] = []
            elif '<h3 id="' in line:
                chal_name = re.findall('<h3 id="(.*?)">', line)[0]
                anchor_name = re.findall('<a class="header-link" href="(.*?)">', line)[0]
                chals[chal_type].append((chal_name, anchor_name))

    mobile_dropdown_string = ''
    desktop_menu_string = ''
    is_first_dropdown_list = True
    for chal_type, chal_info in chals.items():
        items = []
        for chal_name, chal_anchor in chal_info:
            items.append(mobile_dropdown_item(chal_name, chal_anchor))
        item_string = '\n'.join(items)
        mobile_dropdown_string += mobile_dropdown_list(chal_type, item_string, is_first_dropdown_list)
        is_first_dropdown_list = False

    for i, (chal_type, chal_info) in enumerate(chals.items()):
        items = []
        for chal_name, chal_anchor in chal_info:
            items.append(desktop_menu_item(chal_name, chal_anchor))
        item_string = '\n'.join(items)
        desktop_menu_string += desktop_menu_list(chal_type, item_string, i)
    return html.replace('<!-- toc2html-mobile -->', mobile_dropdown_string).replace('<!-- toc2html-desktop -->', desktop_menu_string)

def mobile_dropdown_list(name, item_string, is_first_dropdown_list):
    github_button_iframe = ''
    if is_first_dropdown_list:
        github_button_iframe = '''
              <iframe src="https://ghbtns.com/github-btn.html?user=balsn&repo=ctf_writeup&type=watch&count=true&size=large&v=2" frameborder="0" scrolling="0" width="140px" height="30px"></iframe>
              <iframe src="https://ghbtns.com/github-btn.html?user=balsn&repo=ctf_writeup&type=star&count=true&size=large" frameborder="0" scrolling="0" width="140px" height="30px"></iframe>
        '''
    return f'''
            <li class="nav-item dropdown d-sm-block d-md-none">{github_button_iframe}
              <a class="nav-link dropdown-toggle" href="#" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                {name}
              </a>
              <div class="dropdown-menu" aria-labelledby="smallerscreenmenu">
                {item_string}
              </div>
            </li>
    '''

def mobile_dropdown_item(name, anchor): 
    assert anchor.startswith('#')
    return f'''                <a class="dropdown-item" href="{anchor}">{name}</a>
    '''

def desktop_menu_item(name, anchor):
    assert anchor.startswith('#')
    return f'''<a href="{anchor}" class="list-group-item list-group-item-action text-white bg-dark">
              <span class="menu-collapsed">{name}</span>
            </a>
    '''

def desktop_menu_list(name, item_string, idx):
    return f'''
          <a href="#submenu{idx}" data-toggle="collapse" aria-expanded="false" class="list-group-item list-group-item-action flex-column align-items-start bg-dark">
            <div class="d-flex w-100 justify-content-start align-items-center font-weight-bold">
              <span class="fa fa-dashboard fa-fw mr-3"></span>
              <span class="menu-collapsed">{name}</span>
              <span class="submenu-icon ml-auto"></span>
            </div>
          </a>
          <div id="submenu{idx}" class="collapse sidebar-submenu">
            {item_string}
          </div>
    '''

def parseArgv():
    parser = argparse.ArgumentParser(prog=sys.argv[0])
    parser.add_argument('filename', type=str)
    return parser.parse_args()

if __name__ == '__main__':
    argv = parseArgv()
    main(argv)
