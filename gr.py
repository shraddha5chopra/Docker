import matplotlib.pyplot as plt
import json
import csv
from collections import Counter

def countSeverity(filename):
    with open(filename, "r") as f:
        data = json.loads(f.read())
        keys = data.keys()
        c = Counter()

        for i in keys:
            matches = data[i]["matches"]
            for m in matches:
                severity = m["vulnerability"]["severity"]
                c.update({severity: 1}) 

        return c

def countPackages(filename):
    with open(filename, "r") as f:
        data = json.loads(f.read())
        keys = data.keys()
        c = Counter()

        for i in keys:
            matches = data[i]["matches"]
            for m in matches:
                c.update({m["artifact"]["name"]: 1})
        
        return c

def countImages(filename):
    with open(filename, "r") as f:
        data = json.loads(f.read())
        keys = data.keys()
        c = Counter()

        for i in keys:
            c.update({i: len(data[i]["matches"])})
        
        return c

def groupImages(filename):
    with open(filename, "r") as f:
        data = json.loads(f.read())
        keys = data.keys()
        c = {}
    
    for i in keys:
            matches = data[i]["matches"]
            for m in matches:
                severity = m["vulnerability"]["severity"]
                if severity == "Critical":
                    c.update({i : "Critical"})
                    break
                elif severity == "High":
                    if c.get(i) != "Critical":
                        c.update({i : "High"})
                elif severity == "Medium":
                    if c.get(i) not in ["Critical", "High"]:
                        c.update({i : "Medium"})
                elif severity == "Low":
                    if c.get(i) not in ["Critical", "High", "Medium"]:
                        c.update({i : "Low"})
                elif severity == "Negligible":
                    if c.get(i) not in ["Critical", "High", "Medium", "Low"]:
                        c.update({i : "Negligible"})
                else:
                    c.update({i: "Unknown"}) 
    
    return c

def create_bar_chart(data, xlabel, ylabel, title, filename):
    keys = list(data.keys())
    values = list(data.values())
    plt.bar(keys, values, color='skyblue')
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.title(title)
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig(filename)
    plt.close()

def create_pie_chart(data, title, filename):
    labels = list(data.keys())
    sizes = list(data.values())
    plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
    plt.axis('equal') 
    plt.title(title)
    plt.tight_layout()
    plt.savefig(filename)
    plt.close()

if __name__ == '__main__':
    filename = "scan_results.json"
    
    # 1. Distribution of vulnerability severities
    severity_counts = countSeverity(filename)
    create_bar_chart(severity_counts, 'Severity', 'Count', 'Distribution of Vulnerability Severities', 'severity_distribution.png')

    # 2. Percentage of vulnerabilities by severity
    create_pie_chart(severity_counts, 'Percentage of Vulnerabilities by Severity', 'severity_distribution_pie.png')

    # 3. Top 10 packages with the most vulnerabilities
    package_counts = countPackages(filename)
    top_10_packages = dict(package_counts.most_common(10))
    create_bar_chart(top_10_packages, 'Package', 'Count', 'Top 10 Packages with Most Vulnerabilities', 'top_10_packages.png')

    # 4. Top 10 Docker images with the most vulnerabilities
    image_counts = countImages(filename)
    top_10_images = dict(image_counts.most_common(10))
    create_bar_chart(top_10_images, 'Docker Image', 'Count', 'Top 10 Docker Images with Most Vulnerabilities', 'top_10_images.png')

    # 5. Distribution of severity levels among Docker images
    severity_distribution = groupImages(filename)
    severity_distribution_counts = Counter(severity_distribution.values())
    create_bar_chart(severity_distribution_counts, 'Severity', 'Count', 'Distribution of Severity Levels Among Docker Images', 'severity_distribution_docker.png')
