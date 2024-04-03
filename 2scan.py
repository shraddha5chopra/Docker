import os
import json

def pullImages():
        file = open("image_list.txt", "r")
        failed_file = open("failed_images.txt", "w")
        scan_results_file = open("scan_results.out", "w")
        HR_scan_results_file = open("HR_scan_results.out", "w")
        images = file.read().split()
        results = {}
        for i in range(0,50):
            try:
                print("Pulling: " + images[i])
                exit_code = os.system("docker pull " + images[i])
                if(exit_code != 0):
                    print("Failed to pull: " + images[i])
                    failed_file.write("failed to pull image: " + images[i] + "\n")
                
                #scan the image
                print("Scanning: " + images[i])
                data = os.popen(
                    "grype " + images[i] +" -o json").read()
                results[images[i]] = json.loads(data)
                
                #remove the image
                print("Removing: " + images[i])
                exit_code = os.system("docker rmi " + images[i] + " -f")
                if(exit_code != 0):
                    print("Failed to remove: " + images[i])
                    failed_file.write("failed to remove image: " + images[i] + "\n")
            except:
                print("Exception on: " + images[i])
                failed_file.write("Exception on: " + images[i] + "\n")
                pass

        scan_results_file.write(json.dumps(results))
        HR_scan_results_file.write(json.dumps(results, indent=1))
        file.close()
        failed_file.close()
        scan_results_file.close()
        HR_scan_results_file.close()

if __name__ == '__main__':
    pullImages()