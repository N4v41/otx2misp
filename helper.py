
def show_att(key, att):
    if type(att) == list and len(att) == 0:
        print("\t\t [-] " + key + ": " + "Unknown")
    elif (att != None) and (att != " ") and (att != ''):
        print("\t\t [-] "+key+": " + str(att))
    else:
        print("\t\t [-] "+key+": " + "Unknown")


def show_tags(tags):
    tag_chain = ""
    if len(tags)>0:
        for tag in tags:
            tag_chain = tag_chain + "#"+tag.replace(" " , "")+" "
        print("\t\t [-] Tags: " + tag_chain.strip())


def show_ioc(ioc):
    print("\t\t\t [-] New IoC with ID: " + str(ioc['id']))
    print("\t\t\t\t [-] IoC: " + str(ioc['indicator']))
    print("\t\t\t\t [-] type: " + ioc['type'])
    if (ioc['content'] != None) and (ioc['content'] != " ") and (ioc['content'] != ''):
        print("\t\t\t\t [-] Content: " + ioc['content'].replace("\n", "\n\t\t\t\t\t"))
    print("\t\t\t\t [-] created: " + str(ioc['created']))
    if (ioc['title'] != '') and (ioc['title'] != None):
        print("\t\t\t\t [-] title: " + str(ioc['title']))
    if ioc['description'] != '':
        print("\t\t\t\t [-] description: " + str(ioc['description']))
    if ioc['role'] != None and ioc['role'] != '':
        print("\t\t\t\t [-] role: " + str(ioc['role']))


def show_references(references):
    if len(references) > 0:
        print("\t\t [-] References: ")
        for r in references:
            print("\t\t\t [+] link: "+r)


def show_pulse(pulse):
    global verbosity
    print("\t[+] New OTX Pulse by "+ pulse['author_name'] + ' created: '+pulse['created'])
    if pulse['modified'] != '':
        print("\t\t [-] This pulse was edited: "+pulse['modified'])
    print("\t\t [-] Title: " + pulse['name'])
    print("\t\t [-] ID: " + pulse['id'])
    print("\t\t [-] TLP: " + pulse['tlp'])
    if verbosity >= 2:
        show_att("Description", pulse['description'])
        show_att("Malware families", pulse['malware_families'])
        show_att("Targeted countries", pulse['targeted_countries'])
        show_att("Adversary", pulse['adversary'])
        show_att("ATT&CK Techniques", pulse['attack_ids'])
        show_tags(pulse["tags"])
        show_references(pulse['references'])
    if verbosity >= 3:
        print("\t\t [-] IoCs associated with this pulse:")
        for ioc in pulse['indicators']:
            show_ioc(ioc)