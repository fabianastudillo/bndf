import runpy


def main():
    runpy.run_path(path_name='fingerprint_generator.py -d ' + '-o ' + '-w "/root/whitelist.txt" -i "elasticsearch"')

if __name__ == "__main__":
    main()