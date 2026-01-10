import requests
import sys
import getpass

# --- 配置部分 ---
API_BASE_URL = "https://api.digitalocean.com/v2"


class DOManager:
    def __init__(self):
        self.token = ""
        self.headers = {}
        self.regions = []
        self.images = []
        self.sizes = []

    def auth(self):
        """用户认证，获取Token"""
        print("\n" + "=" * 50)
        print("   DigitalOcean 简易管理面板 (不保存Token)")
        print("=" * 50)
        print("请输入您的 DigitalOcean API Token (输入时不可见):")

        self.token = getpass.getpass("Token > ").strip()
        if not self.token:
            print("[!] Token 不能为空，程序退出。")
            sys.exit(1)

        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }

        print("[-] 正在验证 Token...")
        try:
            resp = requests.get(f"{API_BASE_URL}/account", headers=self.headers, timeout=10)
            if resp.status_code == 200:
                email = resp.json().get("account", {}).get("email")
                print(f"[+] 验证成功! 当前账户: {email}")
            else:
                print(f"[!] Token 无效或未授权 (状态码: {resp.status_code})。")
                try:
                    print("返回信息：", resp.text)
                except Exception:
                    pass
                sys.exit(1)
        except requests.RequestException as e:
            print(f"[!] 连接 API 失败: {e}")
            sys.exit(1)

    def fetch_data(self):
        """拉取基础数据：区域、镜像、规格"""
        print("[-] 正在拉取最新的区域、镜像和规格信息，请稍候...")

        try:
            # 1. Regions
            r_resp = requests.get(
                f"{API_BASE_URL}/regions",
                headers=self.headers,
                params={"per_page": 200},
                timeout=15,
            )
            r_resp.raise_for_status()
            all_regions = r_resp.json().get("regions", [])
            self.regions = [r for r in all_regions if r.get("available")]

            # 2. Images (distribution)
            i_resp = requests.get(
                f"{API_BASE_URL}/images",
                headers=self.headers,
                params={"type": "distribution", "per_page": 200},
                timeout=20,
            )
            i_resp.raise_for_status()
            all_images = i_resp.json().get("images", [])
            self.images = [i for i in all_images if i.get("status") == "available"]

            def img_sort_key(x):
                return (str(x.get("distribution", "")), str(x.get("name", "")))

            self.images.sort(key=img_sort_key)

            # 3. Sizes
            s_resp = requests.get(
                f"{API_BASE_URL}/sizes",
                headers=self.headers,
                params={"per_page": 200},
                timeout=20,
            )
            s_resp.raise_for_status()
            all_sizes = s_resp.json().get("sizes", [])

            # 过滤：available + 1vcpu（保持你原来“简洁便宜”思路）
            filtered = []
            for s in all_sizes:
                if not s.get("available"):
                    continue
                slug = str(s.get("slug", ""))
                if "1vcpu" not in slug:
                    continue
                filtered.append(s)

            # 如果过滤后为空，则退一步
            if not filtered:
                filtered = [s for s in all_sizes if s.get("available")]

            self.sizes = sorted(filtered, key=lambda x: float(x.get("price_monthly", 0)))

        except requests.HTTPError as e:
            print(f"[!] 拉取数据失败(HTTP): {e}")
            return False
        except requests.RequestException as e:
            print(f"[!] 拉取数据失败(网络): {e}")
            return False
        except ValueError as e:
            print(f"[!] 拉取数据失败(JSON解析): {e}")
            return False
        except Exception as e:
            print(f"[!] 拉取数据失败: {e}")
            return False

        if not self.regions:
            print("[!] 未获取到可用 Regions。")
            return False
        if not self.images:
            print("[!] 未获取到可用 Images。")
            return False
        if not self.sizes:
            print("[!] 未获取到可用 Sizes。")
            return False

        return True

    def create_droplet(self):
        """创建机器流程"""
        if not self.regions or not self.images or not self.sizes:
            ok = self.fetch_data()
            if not ok:
                return

        print("\n--- 创建新机器 ---")

        # 1) Region
        print("\n[可用区域]:")
        valid_regions = []
        for idx, r in enumerate(self.regions):
            name = r.get("name", "N/A")
            slug = r.get("slug", "N/A")
            print(f"{idx + 1}. {name} ({slug})")
            valid_regions.append(slug)

        r_idx = input("\n请选择区域序号 > ").strip()
        if not r_idx.isdigit() or not (1 <= int(r_idx) <= len(valid_regions)):
            print("[!] 输入错误。")
            return
        selected_region = valid_regions[int(r_idx) - 1]

        # 2) Image
        print("\n[可用系统] (仅显示前 30 个):")
        display_images = self.images[:30]
        valid_images = []
        for idx, img in enumerate(display_images):
            dist = img.get("distribution", "N/A")
            name = img.get("name", "N/A")
            slug = img.get("slug")
            img_id = img.get("id")
            show_id = slug if slug else img_id
            print(f"{idx + 1}. {dist} {name} ({show_id})")
            valid_images.append(slug if slug else img_id)

        i_idx = input("\n请选择系统序号 > ").strip()
        if not i_idx.isdigit() or not (1 <= int(i_idx) <= len(valid_images)):
            print("[!] 输入错误。")
            return
        selected_image = valid_images[int(i_idx) - 1]
        if selected_image is None:
            print("[!] 该镜像缺少 slug/id，无法使用。")
            return

        # 3) Size
        print("\n[可用配置 (价格从低到高)]:")
        valid_sizes = []
        show_sizes = self.sizes[:15]
        for idx, s in enumerate(show_sizes):
            price = s.get("price_monthly", "N/A")
            mem = s.get("memory", "N/A")
            disk = s.get("disk", "N/A")
            slug = s.get("slug", "N/A")
            print(f"{idx + 1}. ${price}/mo - RAM:{mem}MB - Disk:{disk}GB ({slug})")
            valid_sizes.append(slug)

        s_idx = input("\n请选择配置序号 > ").strip()
        if not s_idx.isdigit() or not (1 <= int(s_idx) <= len(valid_sizes)):
            print("[!] 输入错误。")
            return
        selected_size = valid_sizes[int(s_idx) - 1]

        # 4) Basic settings
        name = input("\n请输入机器名称 (例如 web-01) > ").strip()
        if not name:
            name = "droplet-generated"

        ipv6_input = input("是否开启 IPv6? (y/n) > ").strip().lower()
        enable_ipv6 = True if ipv6_input == "y" else False

        # ✅ 默认 root 密码：回车不输入则使用默认
        DEFAULT_ROOT_PASS = "258@45@6Wzy"
        root_pass = getpass.getpass("请设置 Root 密码 (直接回车使用默认) > ").strip()
        if not root_pass:
            root_pass = DEFAULT_ROOT_PASS
            print(f"[*] 未输入密码，将使用默认 Root 密码: {DEFAULT_ROOT_PASS}")

        # Cloud-init user_data
        user_data = f"""#cloud-config
chpasswd:
  list: |
    root:{root_pass}
  expire: False
ssh_pwauth: True
"""

        payload = {
            "name": name,
            "region": selected_region,
            "size": selected_size,
            "image": selected_image,
            "ipv6": enable_ipv6,
            "user_data": user_data,
            "tags": ["script-generated"],
        }

        print(f"\n[-] 正在创建机器 [{name}] ({selected_region})...")
        try:
            resp = requests.post(
                f"{API_BASE_URL}/droplets",
                headers=self.headers,
                json=payload,
                timeout=30,
            )
            if resp.status_code in (200, 201, 202):
                data = resp.json().get("droplet", {})
                d_id = data.get("id")
                print(f"[+] 创建成功! ID: {d_id}")
                print("[*] 注意：机器启动和 cloud-init 配置密码需要 1-2 分钟，请稍候再尝试 SSH 连接。")
            else:
                print(f"[!] 创建失败 (状态码: {resp.status_code})")
                try:
                    print(resp.text)
                except Exception:
                    pass
        except requests.RequestException as e:
            print(f"[!] 请求出错: {e}")

    def list_droplets(self):
        """列出当前所有机器（带序号 No=1/2/3...）"""
        print("\n--- 当前机器列表 ---")
        try:
            resp = requests.get(
                f"{API_BASE_URL}/droplets",
                headers=self.headers,
                params={"per_page": 200},
                timeout=20,
            )

            if resp.status_code != 200:
                print(f"[!] 获取列表失败 (状态码: {resp.status_code})")
                try:
                    print(resp.text)
                except Exception:
                    pass
                return []

            droplets = resp.json().get("droplets", [])
            if not droplets:
                print("[-] 当前没有机器。")
                return []

            print(f"{'No':<4} {'ID':<15} {'Name':<20} {'IP Address':<20} {'Status':<10} {'Region':<10}")
            print("-" * 90)

            for idx, d in enumerate(droplets, start=1):
                d_id = str(d.get("id", "N/A"))
                name = str(d.get("name", "N/A"))[:18]
                status = str(d.get("status", "N/A"))
                region = str(d.get("region", {}).get("slug", "N/A"))

                ip = "N/A"
                for net in d.get("networks", {}).get("v4", []):
                    if net.get("type") == "public":
                        ip = net.get("ip_address", "N/A")
                        break

                print(f"{idx:<4} {d_id:<15} {name:<20} {ip:<20} {status:<10} {region:<10}")

            return droplets

        except requests.RequestException as e:
            print(f"[!] 获取列表失败: {e}")
            return []
        except ValueError as e:
            print(f"[!] 获取列表失败(JSON解析): {e}")
            return []
        except Exception as e:
            print(f"[!] 获取列表失败: {e}")
            return []

    def delete_droplet(self):
        """删除机器（支持输入序号或真实 ID）"""
        droplets = self.list_droplets()
        if not droplets:
            return

        print("\n提示：你可以输入【序号】或【机器ID】")
        target = input("请输入要删除的机器 (输入 q 取消) > ").strip()

        if target.lower() == "q":
            return

        target_id = None

        # ① 输入序号：1/2/3...
        if target.isdigit():
            num = int(target)
            if 1 <= num <= len(droplets):
                target_id = str(droplets[num - 1].get("id"))
            else:
                print("[!] 序号超出范围。")
                return
        else:
            # ② 输入真实ID
            for d in droplets:
                if str(d.get("id")) == target:
                    target_id = target
                    break

        if not target_id:
            print("[!] 未找到对应的机器。")
            return

        confirm = input(f"确认删除 ID {target_id}? (输入 yes 确认) > ").strip()
        if confirm.lower() != "yes":
            print("[-] 操作已取消。")
            return

        try:
            print("[-] 正在删除...")
            resp = requests.delete(
                f"{API_BASE_URL}/droplets/{target_id}",
                headers=self.headers,
                timeout=20,
            )
            if resp.status_code == 204:
                print(f"[+] 机器 {target_id} 删除成功。")
            else:
                print(f"[!] 删除失败 (状态码: {resp.status_code})")
                try:
                    print(resp.text)
                except Exception:
                    pass
        except requests.RequestException as e:
            print(f"[!] 请求出错: {e}")

    def main_menu(self):
        self.auth()
        while True:
            print("\n" + "=" * 30)
            print("   主菜单")
            print("=" * 30)
            print("1. 创建机器 (Create)")
            print("2. 删除机器 (Delete)")
            print("3. 查看列表 (List)")
            print("4. 退出 (Exit)")

            choice = input("\n请选择 > ").strip()

            if choice == "1":
                self.create_droplet()
            elif choice == "2":
                self.delete_droplet()
            elif choice == "3":
                self.list_droplets()
            elif choice == "4":
                print("Bye!")
                break
            else:
                print("无效输入")


if __name__ == "__main__":
    try:
        app = DOManager()
        app.main_menu()
    except KeyboardInterrupt:
        print("\n\n程序强制退出。")
        sys.exit(0)
