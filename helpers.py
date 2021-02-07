tag_list = ["Architecture", "Environments", "Input and Error Handling", "Database", "DR & BC",
            "Version Management & Updates", "Logging & Monitoring", "Password Policy", "Encryption", "Sensitive Data",
            "Documentation & Legal Agreements", "Hardening", "Security Systems", "Configuration",
            "Users Permissions & Authentication", "Firewall", "Remote Access", "Policies & Procedures",
            "Development", "PT", "Infrastructure", "Mobile", "Web", "Client", "Reconnaissance", "Phishing",
            "Supply Chain", "Communication & Protocols", "Hijack", "Remote Code Execution", "Persistence",
            "Privilege Escalation", "Evasion", "Credentials", "Lateral Movement", "File Upload", "Token",
            "Obfuscation", "Denial of Service", "Injection", "XSS", "Virtualization", "Cloud", "Encoding",
            "Man In The Middle", "Local File Inclusion", "Remote File Inclusion"]




def search_results(keywords, tags_list, item):
    title = item['Title']
    title_strip = title.strip().split(' ')
    body = item['Description']
    body_strip = body.strip().split(' ')
    details = item['RiskDetails']
    details_strip = details.strip().split(' ')
    tags = item['Tags']
    tags_strip = tags.strip().split(',')

    if any(i in tags_list for i in tags_strip):
        return True
    elif any(i in keywords for i in title_strip) or any(i in keywords for i in body_strip) or any(i in keywords for i in details_strip):
        return True

