#!/usr/bin/env bash
# ERPNext Quick Installer (enhanced)
# - Includes Supervisor pre-install + config
# - Includes Nginx vhosts.yml condition + PID cleanup before production setup
# - Safer defaults, non-root guard, dynamic user detection
#
# Usage:
#   chmod +x erpnext_install.sh
#   ./erpnext_install.sh
#
# Notes:
# - Run as a non-root sudoer (recommended). The script uses sudo when needed.
# - Tested on Ubuntu 22.04/24.04 and Debian 12 for ERPNext v15.
# - For older ERPNext versions, Debian/Ubuntu ranges are handled below.

set -Eeuo pipefail

handle_error() {
  local line=$1
  local exit_code=${2:-$?}
  echo "An error occurred on line $line with exit status $exit_code"
  exit "$exit_code"
}
trap 'handle_error $LINENO $?' ERR

# -----------------------------
# Basic env & user detection
# -----------------------------
RUN_USER="${SUDO_USER:-${USER}}"
RUN_HOME="$(getent passwd "$RUN_USER" | cut -d: -f6 || echo "$HOME")"
SERVER_IP="$(hostname -I | awk '{print $1}')"

YELLOW='\033[1;33m'
GREEN='\033[0;32m'
RED='\033[0;31m'
LIGHT_BLUE='\033[1;34m'
NC='\033[0m'

# Default bench folder name (can be overridden later by prompt)
bench_name="frappe-bench"

if [[ "${EUID}" -eq 0 ]]; then
  echo -e "${RED}Do not run this script as root. Please use a non-root sudoer account.${NC}"
  exit 1
fi

# Ensure required OS tools
sudo apt-get update -y
sudo apt-get install -y lsb-release

SUPPORTED_DISTRIBUTIONS=("Ubuntu" "Debian")
SUPPORTED_VERSIONS=("24.04" "23.04" "22.04" "20.04" "12" "11" "10" "9" "8")

check_os() {
  local os_name os_version os_supported=false version_supported=false
  os_name="$(lsb_release -is)"
  os_version="$(lsb_release -rs)"

  for i in "${SUPPORTED_DISTRIBUTIONS[@]}"; do
    if [[ "$i" = "$os_name" ]]; then os_supported=true; break; fi
  done
  for i in "${SUPPORTED_VERSIONS[@]}"; do
    if [[ "$i" = "$os_version" ]]; then version_supported=true; break; fi
  done

  if [[ "$os_supported" = false ]] || [[ "$version_supported" = false ]]; then
    echo -e "${RED}This script is not compatible with your operating system or its version.${NC}"
    echo "Detected: $os_name $os_version"
    exit 1
  fi
}
check_os

# Detect distro family
DISTRO=''
if [[ -f /etc/debian_version ]]; then
  if [[ "$(lsb_release -si)" == "Ubuntu" ]]; then
    DISTRO='Ubuntu'
  else
    DISTRO='Debian'
  fi
fi

ask_twice() {
  local prompt="$1"; local secret="$2"; local val1 val2
  while true; do
    if [[ "$secret" == "true" ]]; then read -rsp "$prompt: " val1; echo >&2
    else read -rp "$prompt: " val1; echo >&2; fi
    if [[ "$secret" == "true" ]]; then read -rsp "Confirm password: " val2; echo >&2
    else read -rp "Confirm password: " val2; echo >&2; fi
    if [[ "$val1" == "$val2" ]]; then
      printf "${GREEN}Password confirmed${NC}\n" >&2
      echo "$val1"; break
    else
      printf "${RED}Inputs do not match. Please try again${NC}\n" >&2; echo -e "\n"
    fi
  done
}

extract_app_name_from_setup() {
  local setup_file="$1" app_name=""
  [[ -f "$setup_file" ]] || { echo ""; return 0; }
  app_name=$(grep -oE 'name\s*=\s*["'\''][^"\'']+["'\'']' "$setup_file" 2>/dev/null | head -1 | sed -E 's/.*name\s*=\s*["'\'']([^"\'']+)["'\''].*/\1/')
  if [[ -z "$app_name" ]]; then
    app_name=$(awk '/setup\s*\(/,/\)/ { if (/name\s*=/) { gsub(/.*name\s*=\s*["'\'']/, ""); gsub(/["'\''].*/, ""); print; exit } }' "$setup_file" 2>/dev/null | head -1 | tr -d ' \t')
  fi
  if [[ -z "$app_name" ]]; then
    local app_base_dir; app_base_dir=$(dirname "$setup_file")
    for subdir in "$app_base_dir"/*/; do
      if [[ -d "$subdir" && -f "$subdir/__init__.py" ]]; then
        local module_dir; module_dir=$(basename "$subdir")
        if [[ -n "$module_dir" && "$module_dir" != "tests" && "$module_dir" != "docs" ]]; then
          app_name="$module_dir"; break
        fi
      fi
    done
  fi
  echo "$app_name"
}

check_existing_installations() {
  local existing_installations=()
  local installation_paths=()

  local search_paths=(
    "$RUN_HOME/$bench_name"
    "/home/*/$bench_name"
    "/opt/$bench_name"
    "/var/www/$bench_name"
    "/home/*/frappe-bench"
    "/opt/frappe-bench"
  )

  echo -e "${YELLOW}Checking for existing ERPNext installations...${NC}"
  for path in "${search_paths[@]}"; do
    if [[ -d $path && -f "$path/apps/frappe/frappe/__init__.py" ]]; then
      local version_info="unknown" branch_info="unknown"
      [[ -f "$path/apps/frappe/frappe/__version__.py" ]] && version_info=$(grep -o 'version.*=.*[0-9]' "$path/apps/frappe/frappe/__version__.py" || echo "unknown")
      [[ -d "$path/apps/frappe/.git" ]] && branch_info=$(git -C "$path/apps/frappe" branch --show-current 2>/dev/null || echo "unknown")
      existing_installations+=("$path")
      installation_paths+=("Path: $path | Version: $version_info | Branch: $branch_info")
    fi
  done

  if [[ ${#existing_installations[@]} -gt 0 ]]; then
    echo -e "\n${RED}⚠️ EXISTING ERPNEXT INSTALLATION(S) DETECTED ⚠️${NC}\n"
    echo -e "${YELLOW}Found the following ERPNext installation(s):${NC}"
    for info in "${installation_paths[@]}"; do
      echo -e "${LIGHT_BLUE}• $info${NC}"
    done
    echo -e "\n${LIGHT_BLUE}Recommended actions:${NC}"
    echo -e "${GREEN}1. Use the existing installation if it meets your needs${NC}"
    echo -e "${GREEN}2. Backup and remove existing installation before installing new version${NC}"
    echo -e "${GREEN}3. Use a fresh server/container for the new installation${NC}"
    echo -e "${GREEN}4. Use different users/paths if you must have multiple versions${NC}\n"
    read -rp "Do you want to continue anyway? (yes/no): " conflict_confirm
    conflict_confirm=$(echo "$conflict_confirm" | tr '[:upper:]' '[:lower:]')
    if [[ "$conflict_confirm" != "yes" && "$conflict_confirm" != "y" ]]; then
      echo -e "${GREEN}Installation cancelled. Good choice for system stability!${NC}"
      exit 0
    else
      echo -e "${YELLOW}Proceeding with installation despite existing installations...${NC}"
      echo -e "${RED}You've been warned about potential conflicts!${NC}"
    fi
  else
    echo -e "${GREEN}✓ No existing ERPNext installations found.${NC}"
  fi
}

detect_best_branch() {
  local repo_url="$1" preferred_version="$2" repo_name="$3"
  echo -e "${LIGHT_BLUE}🔍 Detecting available branches for $repo_name...${NC}" >&2
  local branches; branches=$(git ls-remote --heads "$repo_url" 2>/dev/null | awk '{print $2}' | sed 's|refs/heads/||' | sort -V || true)
  if [[ -z "${branches:-}" ]]; then
    echo -e "${RED}⚠ Could not fetch branches from $repo_url${NC}" >&2
    echo ""; return 1
  fi

  case "$repo_name" in
    crm|helpdesk|builder|drive|gameplan)
      if echo "$branches" | grep -q "^main$"; then echo "main"; return 0
      elif echo "$branches" | grep -q "^master$"; then echo "master"; return 0; fi
      ;;
  esac

  local branch_priorities=()
  case "$preferred_version" in
    version-15|develop) branch_priorities=(version-15 develop main master version-14 version-13);;
    version-14) branch_priorities=(version-14 main master develop version-15 version-13);;
    version-13) branch_priorities=(version-13 main master version-14 develop version-15);;
    *) branch_priorities=(main master develop);;
  esac

  for b in "${branch_priorities[@]}"; do
    if echo "$branches" | grep -q "^$b$"; then echo "$b"; return 0; fi
  done
  echo "$branches" | head -1
}

echo -e "${LIGHT_BLUE}Welcome to the ERPNext Installer...${NC}\n"
sleep 1

echo -e "${YELLOW}Please enter the number of the corresponding ERPNext version you wish to install:${NC}"
versions=("Version 13" "Version 14" "Version 15" "Develop")
select version_choice in "${versions[@]}"; do
  case $REPLY in
    1) bench_version="version-13"; break;;
    2) bench_version="version-14"; break;;
    3) bench_version="version-15"; break;;
    4) bench_version="develop";
       echo -e "\n${RED}⚠️ WARNING: DEVELOP VERSION ⚠️${NC}\n"
       echo -e "${YELLOW}The develop branch is unstable and not for production.${NC}\n"
       read -rp "Do you understand the risks and want to continue? (yes/no): " develop_confirm
       develop_confirm=$(echo "$develop_confirm" | tr '[:upper:]' '[:lower:]')
       [[ "$develop_confirm" == "yes" || "$develop_confirm" == "y" ]] || continue
       ;;
    *) echo -e "${RED}Invalid option. Please select a valid version.${NC}";;
  esac
done

echo -e "${GREEN}You have selected $version_choice for installation.${NC}"
read -rp "$(echo -e ${LIGHT_BLUE}Do\ you\ wish\ to\ continue?\ \(\yes/no\)\ ${NC})" continue_install
continue_install=$(echo "$continue_install" | tr '[:upper:]' '[:lower:]')
[[ "$continue_install" == "yes" || "$continue_install" == "y" ]] || { echo -e "${RED}Installation aborted by user.${NC}"; exit 0; }

check_existing_installations

# -----------------------------
# Version / OS compatibility
# -----------------------------
if [[ "$bench_version" == "version-15" || "$bench_version" == "develop" ]]; then
  if [[ "$(lsb_release -si)" == "Ubuntu" && "$(lsb_release -rs)" < "22.04" ]]; then
    echo -e "${RED}Ubuntu below 22.04 is not supported for v15/develop.${NC}"; exit 1
  elif [[ "$(lsb_release -si)" == "Debian" && "$(lsb_release -rs)" < "12" ]]; then
    echo -e "${RED}Debian below 12 is not supported for v15/develop.${NC}"; exit 1
  fi
else
  if [[ "$(lsb_release -si)" == "Ubuntu" && "$(lsb_release -rs)" > "22.04" ]]; then
    echo -e "${RED}For Ubuntu > 22.04, please use ERPNext v15.${NC}"; exit 1
  elif [[ "$(lsb_release -si)" == "Debian" && "$(lsb_release -rs)" > "11" ]]; then
    echo -e "${YELLOW}Debian above 11 is untested for $version_choice — continuing anyway.${NC}"
  fi
fi

cd "$RUN_HOME"

# -----------------------------
# SQL root password
# -----------------------------
echo -e "${YELLOW}We will need your required SQL root password${NC}"
sqlpasswrd="$(ask_twice 'What is your required SQL root password' true)"
echo

# -----------------------------
# System updates & base packages
# -----------------------------
echo -e "${YELLOW}Updating system packages...${NC}"
sudo apt-get update -y
sudo apt-get upgrade -y
echo -e "${GREEN}System packages updated.${NC}"

echo -e "${YELLOW}Installing preliminary package requirements...${NC}"
sudo apt-get install -y software-properties-common git curl whiptail cron dialog build-essential

# -----------------------------------------------------------------
# PRELIMINARY Supervisor install fix (before Python/Redis install)
# -----------------------------------------------------------------
echo "📦 Installing Supervisor and creating default config..."
sudo apt-get install -y supervisor
sudo mkdir -p /var/log/supervisor
sudo mkdir -p /etc/supervisor/conf.d

if [[ ! -f /etc/supervisor/supervisord.conf ]]; then
  sudo tee /etc/supervisor/supervisord.conf > /dev/null <<EOF
[unix_http_server]
file=/var/run/supervisor.sock
chmod=0700
chown=${RUN_USER}:${RUN_USER}

[supervisord]
logfile=/var/log/supervisor/supervisord.log
pidfile=/var/run/supervisord.pid
childlogdir=/var/log/supervisor

[rpcinterface:supervisor]
supervisor.rpcinterface_factory = supervisor.rpcinterface:make_main_rpcinterface

[supervisorctl]
serverurl=unix:///var/run/supervisor.sock

[include]
files = /etc/supervisor/conf.d/*.conf
EOF
fi
sudo systemctl enable supervisor
sudo systemctl restart supervisor

# -----------------------------
# Python & Redis
# -----------------------------
echo -e "${YELLOW}Installing python environment manager and other requirements...${NC}"
py_version="$(python3 --version 2>&1 | awk '{print $2}' || true)"
py_major="${py_version%%.*}"; py_minor="${py_version#*.}"; py_minor="${py_minor%%.*}"

if [[ -z "${py_version:-}" || "$py_major" -lt 3 || ( "$py_major" -eq 3 && "$py_minor" -lt 10 ) ]]; then
  echo -e "${YELLOW}Installing Python 3.10...${NC}"
  sudo apt-get install -y zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev \
      libssl-dev libreadline-dev libffi-dev libsqlite3-dev wget libbz2-dev
  wget -q https://www.python.org/ftp/python/3.10.11/Python-3.10.11.tgz
  tar -xf Python-3.10.11.tgz
  pushd Python-3.10.11 >/dev/null
  ./configure --prefix=/usr/local --enable-optimizations --enable-shared LDFLAGS="-Wl,-rpath /usr/local/lib"
  make -j"$(nproc)"
  sudo make altinstall
  popd >/dev/null
  rm -rf Python-3.10.11 Python-3.10.11.tgz
  pip3.10 install --user --upgrade pip
  echo -e "${GREEN}Python3.10 installation successful!${NC}"
fi

echo -e "${YELLOW}Installing additional Python packages and Redis Server${NC}"
sudo apt-get install -y python3-dev python3-setuptools python3-venv python3-pip redis-server

# -----------------------------
# wkhtmltopdf
# -----------------------------
arch="$(uname -m)"
case "$arch" in
  x86_64) arch="amd64" ;;
  aarch64) arch="arm64" ;;
  *) echo -e "${RED}Unsupported architecture: $(uname -m)${NC}"; exit 1 ;;
esac

sudo apt-get install -y fontconfig libxrender1 xfonts-75dpi xfonts-base xvfb
wget -q "https://github.com/wkhtmltopdf/packaging/releases/download/0.12.6.1-2/wkhtmltox_0.12.6.1-2.jammy_${arch}.deb"
sudo dpkg -i "wkhtmltox_0.12.6.1-2.jammy_${arch}.deb" || true
sudo cp /usr/local/bin/wkhtmlto* /usr/bin/ || true
sudo chmod a+x /usr/bin/wk* || true
rm -f "wkhtmltox_0.12.6.1-2.jammy_${arch}.deb"
sudo apt-get -f install -y

# -----------------------------
# MariaDB
# -----------------------------
echo -e "${YELLOW}Now installing MariaDB and dev libraries...${NC}"
sudo apt-get install -y mariadb-server mariadb-client pkg-config default-libmysqlclient-dev

MARKER_FILE="${RUN_HOME}/.mysql_configured.marker"
if [[ ! -f "$MARKER_FILE" ]]; then
  echo -e "${YELLOW}Securing MariaDB...${NC}"
  sudo mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '${sqlpasswrd}';"
  sudo mysql -u root -p"${sqlpasswrd}" -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '${sqlpasswrd}';"
  sudo mysql -u root -p"${sqlpasswrd}" -e "DELETE FROM mysql.user WHERE User='';"
  sudo mysql -u root -p"${sqlpasswrd}" -e "DROP DATABASE IF EXISTS test; DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';"
  sudo mysql -u root -p"${sqlpasswrd}" -e "FLUSH PRIVILEGES;"
  sudo bash -c 'cat << EOF >> /etc/mysql/my.cnf
[mysqld]
character-set-client-handshake = FALSE
character-set-server = utf8mb4
collation-server = utf8mb4_unicode_ci
[mysql]
default-character-set = utf8mb4
EOF'
  sudo systemctl restart mariadb
  sudo -u "$RUN_USER" touch "$MARKER_FILE"
  echo -e "${GREEN}MariaDB secured.${NC}"
fi

# -----------------------------
# NVM / Node / Yarn
# -----------------------------
echo -e "${YELLOW}Installing NVM/Node/Yarn...${NC}"
# Install nvm for the RUN_USER environment
sudo -u "$RUN_USER" bash -lc 'export PROFILE="$HOME/.bashrc"; curl -fsSL https://raw.githubusercontent.com/creationix/nvm/master/install.sh | bash'
NVM_INIT='export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
[ -s "$NVM_DIR/bash_completion" ] && \. "$NVM_DIR/bash_completion"'
for f in "$RUN_HOME/.profile" "$RUN_HOME/.bashrc"; do
  grep -qxF 'export NVM_DIR="$HOME/.nvm"' "$f" 2>/dev/null || echo "$NVM_INIT" | sudo tee -a "$f" >/dev/null
done

os_version="$(lsb_release -rs)"
if [[ "$DISTRO" == "Ubuntu" && "$os_version" == "24.04" ]]; then
  NODE_VER=20
elif [[ "$bench_version" == "version-15" || "$bench_version" == "develop" ]]; then
  NODE_VER=18
else
  NODE_VER=16
fi

sudo -u "$RUN_USER" bash -lc "source \"$RUN_HOME/.nvm/nvm.sh\" && nvm install ${NODE_VER} && nvm alias default ${NODE_VER} && npm install -g yarn@1.22.19"
echo -e "${GREEN}Node ${NODE_VER} + Yarn installed.${NC}"

# -----------------------------
# Bench install
# -----------------------------
echo -e "${YELLOW}Installing bench...${NC}"
externally_managed_file=$(find /usr/lib/python3.*/EXTERNALLY-MANAGED 2>/dev/null || true)
if [[ -n "${externally_managed_file:-}" ]]; then
  sudo python3 -m pip config --global set global.break-system-packages true
fi
sudo apt-get install -y python3-pip
sudo pip3 install -U frappe-bench

echo -e "${YELLOW}Enter a name for your bench folder (default: frappe-bench):${NC}"
read -r bench_name_inp || true
bench_name="${bench_name_inp:-$bench_name}"

echo -e "${YELLOW}Initialising bench in ${bench_name} folder.${NC}"
sudo -u "$RUN_USER" bash -lc "source \"$RUN_HOME/.nvm/nvm.sh\" && bench init \"$bench_name\" --version \"$bench_version\" --verbose"

# -----------------------------
# New site
# -----------------------------
echo -e "${YELLOW}Preparing for Production installation...${NC}"
read -rp "Enter the site name (Use a FQDN if you plan to enable SSL): " site_name
adminpasswrd="$(ask_twice 'Enter the Administrator password' true)"

sudo -u "$RUN_USER" bash -lc "
  cd \"$bench_name\"
  chmod -R o+rx \"$RUN_HOME\"
  bench new-site \"$site_name\" \
    --db-root-username root \
    --db-root-password '$sqlpasswrd' \
    --admin-password '$adminpasswrd'
"

if [[ "$bench_version" == "develop" ]]; then
  echo -e "${YELLOW}Starting Redis instances for develop (queue/cache/socketio)...${NC}"
  sudo -u "$RUN_USER" bash -lc "redis-server --port 11000 --daemonize yes --bind 127.0.0.1"
  sudo -u "$RUN_USER" bash -lc "redis-server --port 12000 --daemonize yes --bind 127.0.0.1"
  sudo -u "$RUN_USER" bash -lc "redis-server --port 13000 --daemonize yes --bind 127.0.0.1"
fi

read -rp "$(echo -e ${LIGHT_BLUE}Would\ you\ like\ to\ install\ ERPNext?\ \(yes/no\)\ ${NC})" erpnext_install
erpnext_install=$(echo "$erpnext_install" | tr '[:upper:]' '[:lower:]')
if [[ "$erpnext_install" == "yes" || "$erpnext_install" == "y" ]]; then
  sudo -u "$RUN_USER" bash -lc "
    source \"$RUN_HOME/.nvm/nvm.sh\"
    cd \"$bench_name\"
    bench get-app erpnext --branch \"$bench_version\"
    bench --site \"$site_name\" install-app erpnext
  "
fi

# Fix include_tasks deprecation path for some distros
python_version="$(python3 -c 'import sys; print(f\"{sys.version_info.major}.{sys.version_info.minor}\")')"
playbook_file="/usr/local/lib/python${python_version}/dist-packages/bench/playbooks/roles/mariadb/tasks/main.yml"
if [[ -f "$playbook_file" ]]; then
  sudo sed -i 's/- include: /- include_tasks: /g' "$playbook_file" || true
fi

read -rp "$(echo -e ${LIGHT_BLUE}Would\ you\ like\ to\ continue\ with\ production\ install?\ \(yes/no\)\ ${NC})" continue_prod
continue_prod=$(echo "$continue_prod" | tr '[:upper:]' '[:lower:]')

if [[ "$continue_prod" == "yes" || "$continue_prod" == "y" ]]; then
  echo -e "${YELLOW}Installing packages and dependencies for Production...${NC}"

  # ------------------------------------------------------------------
  # Nginx vhosts.yml condition + PID cleanup BEFORE bench production
  # ------------------------------------------------------------------
  echo "🔧 Patching Ansible nginx vhosts condition..."
  VHOSTS_TASK_FILE=""
  # find the vhosts.yml path robustly
  while IFS= read -r p; do VHOSTS_TASK_FILE="$p"; done < <(python3 - <<'PY'
import sys,glob
paths=glob.glob('/usr/local/lib/python*/dist-packages/bench/playbooks/roles/nginx/tasks/vhosts.yml')
print(paths[0] if paths else '')
PY
)
  if [[ -n "$VHOSTS_TASK_FILE" && -f "$VHOSTS_TASK_FILE" ]]; then
    sudo sed -i 's/when: nginx_vhosts/when: nginx_vhosts | length > 0/' "$VHOSTS_TASK_FILE" || true
  fi

  echo "🧹 Fixing nginx PID permissions before reload..."
  if ! dpkg -s nginx >/dev/null 2>&1; then
    echo "📦 Nginx not found. Installing it now..."
    sudo apt-get update -y && sudo apt-get install -y nginx
  fi
  sudo systemctl stop nginx 2>/dev/null || true
  sudo rm -f /var/run/nginx.pid || true
  sudo chown root:root /var/run || true
  sudo rm -f /etc/nginx/sites-enabled/default || true
  sudo systemctl start nginx || true
  sudo nginx -t || true

  # Now run bench production setup (twice with supervisor perms fix in between)
  sudo -H bash -lc "bench --version" >/dev/null 2>&1 || true
  yes | sudo bench setup production "$RUN_USER"

  echo -e "${YELLOW}Applying necessary permissions to supervisor...${NC}"
  SUPERV_CONF="/etc/supervisor/supervisord.conf"
  SEARCH="chown=${RUN_USER}:${RUN_USER}"
  if grep -q "^chown=" "$SUPERV_CONF"; then
    sudo sed -i "s|^chown=.*|${SEARCH}|g" "$SUPERV_CONF"
  else
    # insert under [unix_http_server]
    sudo awk -v insert="$SEARCH" '
      BEGIN{added=0}
      /^\[unix_http_server\]/{print; print insert; added=1; next}
      {print}
      END{if(!added) print insert}
    ' "$SUPERV_CONF" | sudo tee "$SUPERV_CONF" >/dev/null
  fi
  sudo systemctl restart supervisor
  yes | sudo bench setup production "$RUN_USER"

  echo -e "${YELLOW}Enabling Scheduler...${NC}"
  sudo -u "$RUN_USER" bash -lc "cd \"$bench_name\" && bench --site \"$site_name\" scheduler enable && bench --site \"$site_name\" scheduler resume"

  if [[ "$bench_version" == "version-15" || "$bench_version" == "develop" ]]; then
    echo -e "${YELLOW}Setting up Socketio, Redis and Supervisor for $bench_version...${NC}"
    sudo -u "$RUN_USER" bash -lc "cd \"$bench_name\" && bench setup socketio && yes | bench setup supervisor && bench setup redis"
    sudo supervisorctl reload || true
  fi

  echo -e "${YELLOW}Restarting bench and services...${NC}"
  sudo chmod 755 "$RUN_HOME"
  sudo systemctl restart redis-server || true
  sudo supervisorctl restart all || true

  echo -e "${GREEN}🎉 Production setup complete!${NC}"

  # -----------------------------
  # Optional: SSL
  # -----------------------------
  read -rp "$(echo -e ${YELLOW}Would\ you\ like\ to\ install\ SSL?\ \(yes/no\)\ ${NC})" continue_ssl
  continue_ssl=$(echo "$continue_ssl" | tr '[:upper:]' '[:lower:]')
  if [[ "$continue_ssl" == "yes" || "$continue_ssl" == "y" ]]; then
    echo -e "${YELLOW}Make sure your domain name points to this server first.${NC}"
    if ! command -v certbot >/dev/null 2>&1; then
      read -rp "Enter your email address: " email_address
      if [[ "$DISTRO" == "Debian" ]]; then
        sudo pip3 uninstall -y cryptography || true
        yes | sudo pip3 install pyopenssl==22.0.0 cryptography==36.0.0 || true
      fi
      sudo apt-get install -y snapd
      sudo snap install core && sudo snap refresh core
      sudo snap install --classic certbot
      sudo ln -sf /snap/bin/certbot /usr/bin/certbot
    else
      read -rp "Enter your email address: " email_address
    fi
    sudo certbot --nginx --non-interactive --agree-tos --email "$email_address" -d "$site_name" || {
      echo -e "${RED}Certbot/NGINX SSL failed. You can retry later with certbot.${NC}"
    }
  else
    echo -e "${YELLOW}Skipping SSL installation.${NC}"
  fi

  echo -e "${GREEN}--------------------------------------------------------------------------------"
  echo -e "Congratulations! ERPNext $version_choice installed."
  echo -e "Prod URL (if DNS/SSL): https://$site_name"
  echo -e "Or local URL: http://$SERVER_IP"
  echo -e "--------------------------------------------------------------------------------${NC}"

else
  # Dev flow
  echo -e "${YELLOW}Getting your site ready for development...${NC}"
  # Select default Node per version
  if [[ "$bench_version" == "version-15" ]]; then NODE_VER=18; else NODE_VER=16; fi
  sudo -u "$RUN_USER" bash -lc "source \"$RUN_HOME/.nvm/nvm.sh\" && nvm alias default ${NODE_VER} && cd \"$bench_name\" && bench use \"$site_name\" && bench build"
  echo -e "${GREEN}-----------------------------------------------------------------------------------------------"
  echo -e "Frappe/ERPNext $version_choice Development Environment ready."
  echo -e "Start: cd \"$bench_name\" && bench start  →  http://$SERVER_IP:8000"
  echo -e "-----------------------------------------------------------------------------------------------${NC}"
fi
