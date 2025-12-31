import os
import subprocess
import shutil
import json   # 추가 ✔


def add_env_variable(variable_name, variable_value):
    check_command = f'grep -q "export {variable_name}=" ~/.bashrc'
    result = subprocess.run(check_command, shell=True)

    if result.returncode == 0:
        print(f"{variable_name} already exists in ~/.bashrc")
    else:
        add_command = f'echo "export {variable_name}={variable_value}" >> ~/.bashrc'
        subprocess.run(add_command, shell=True)
        print(f"{variable_name} added to ~/.bashrc")

        apply_command = ". ~/.bashrc"
        subprocess.run(apply_command, shell=True)
        print("Changes applied.")


def get_github_token():
    token = os.environ.get('GITHUB_TOKEN')

    if token:
        print("GITHUB_TOKEN is already set.")
    else:
        token = input("Enter your GitHub Personal Access Token: ")
        os.environ['GITHUB_TOKEN'] = token
        add_env_variable("GITHUB_TOKEN", token)


def generate_sbom(github_url):
    repo_name = github_url.split('/')[-1].replace(".git", "")

    if os.path.exists(repo_name):
        print(f"Directory {repo_name} already exists. Deleting and reclonin")
        shutil.rmtree(repo_name)

    subprocess.run(["git", "clone", github_url], check=True)

    sbom_file = f"{repo_name}-sbom.json"

    # 🔇 cdxgen stderr는 캡처해서, 실패할 때만 보여주기
    result = subprocess.run(
        ["cdxgen", repo_name, "-o", sbom_file],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print("[ERROR] cdxgen failed:")
        # 여기서만 stderr 출력
        print(result.stderr)
        # 예외 던져서 바로 알 수 있도록
        result.check_returncode()

    # ─────────────────────────────────────
    # SBOM JSON pretty-print (한글 깨짐 방지 & 보기 좋게)
    try:
        with open(sbom_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        with open(sbom_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception:
        # 실패해도 SBOM 자체는 있으니 조용히 무시
        pass

    output_dir = os.path.join(os.getcwd(), "generated_sbom")

    if not os.path.exists(output_dir):
        print(f"Directory {output_dir} does not exist.")
        return

    print(f"SBOM generated: {sbom_file}")

    dest_file_path = os.path.join(output_dir, sbom_file)
    shutil.move(sbom_file, dest_file_path)
    print(f"SBOM generated and moved to: {dest_file_path}")


if __name__ == "__main__":
    get_github_token()
    github_url = input("Enter GitHub repository URL: ")
    generate_sbom(github_url)
