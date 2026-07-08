// Package collector gathers system information from Linux, Windows, and
// network devices through authenticated sessions.
package collector

// VendorEntry maps a Debian/apt package name to its NVD CPE vendor and product.
type VendorEntry struct {
	Vendor  string // CPE vendor (e.g. "openbsd", "linux", "gnu")
	Product string // CPE product (e.g. "openssh", "linux_kernel", "bash")
}

// packageVendorMap maps Debian package names (as returned by dpkg-query) to
// their corresponding NVD CPE vendor/product pairs. This enables proper CPE URI
// generation that matches entries in the NVD CVE database.
//
// Only security-relevant packages are listed — packages that historically
// have had CVEs assigned to them. The map is read-only after init.
var packageVendorMap = map[string]VendorEntry{
	// ---- OS & Kernel ----
	"linux-image-amd64": {Vendor: "linux", Product: "linux_kernel"},
	"linux-image-686":   {Vendor: "linux", Product: "linux_kernel"},
	"linux-image-arm64": {Vendor: "linux", Product: "linux_kernel"},
	"linux-image":       {Vendor: "linux", Product: "linux_kernel"},
	"linux-base":        {Vendor: "linux", Product: "linux_kernel"},
	"systemd":           {Vendor: "freedesktop", Product: "systemd"},
	"systemd-sysv":      {Vendor: "freedesktop", Product: "systemd"},
	"systemd-timesyncd": {Vendor: "freedesktop", Product: "systemd"},
	"systemd-container": {Vendor: "freedesktop", Product: "systemd"},
	"grub-pc":           {Vendor: "gnu", Product: "grub"},
	"grub-efi":          {Vendor: "gnu", Product: "grub"},
	"grub2-common":      {Vendor: "gnu", Product: "grub"},
	"shim":              {Vendor: "shim", Product: "shim"},

	// ---- SSH ----
	"openssh-server":      {Vendor: "openbsd", Product: "openssh"},
	"openssh-client":      {Vendor: "openbsd", Product: "openssh"},
	"openssh-sftp-server": {Vendor: "openbsd", Product: "openssh"},
	"libssh-4":            {Vendor: "libssh", Product: "libssh"},
	"libssh2-1":           {Vendor: "libssh2", Product: "libssh2"},
	"dropbear":            {Vendor: "dropbear_ssh", Product: "dropbear_ssh"},

	// ---- TLS / Crypto ----
	"openssl":             {Vendor: "openssl", Product: "openssl"},
	"libssl3":             {Vendor: "openssl", Product: "openssl"},
	"libssl1.1":           {Vendor: "openssl", Product: "openssl"},
	"libssl-dev":          {Vendor: "openssl", Product: "openssl"},
	"libcrypto++":         {Vendor: "cryptopp", Product: "crypto++"},
	"gnutls":              {Vendor: "gnu", Product: "gnutls"},
	"libgnutls30":         {Vendor: "gnu", Product: "gnutls"},
	"libgnutls-openssl27": {Vendor: "gnu", Product: "gnutls"},
	"libnss3":             {Vendor: "mozilla", Product: "nss"},
	"nss":                 {Vendor: "mozilla", Product: "nss"},
	"ca-certificates":     {Vendor: "mozilla", Product: "nss"},

	// ---- Web Servers ----
	"apache2":      {Vendor: "apache", Product: "http_server"},
	"apache2-bin":  {Vendor: "apache", Product: "http_server"},
	"apache2-data": {Vendor: "apache", Product: "http_server"},
	"nginx":        {Vendor: "nginx", Product: "nginx"},
	"nginx-core":   {Vendor: "nginx", Product: "nginx"},
	"nginx-full":   {Vendor: "nginx", Product: "nginx"},
	"lighttpd":     {Vendor: "lighttpd", Product: "lighttpd"},
	"tomcat9":      {Vendor: "apache", Product: "tomcat"},
	"tomcat10":     {Vendor: "apache", Product: "tomcat"},
	"tomcat":       {Vendor: "apache", Product: "tomcat"},
	"jetty9":       {Vendor: "eclipse", Product: "jetty"},
	"haproxy":      {Vendor: "haproxy", Product: "haproxy"},

	// ---- Databases ----
	"mysql-server":      {Vendor: "oracle", Product: "mysql"},
	"mysql-client":      {Vendor: "oracle", Product: "mysql"},
	"mariadb-server":    {Vendor: "mariadb", Product: "mariadb"},
	"mariadb-client":    {Vendor: "mariadb", Product: "mariadb"},
	"postgresql":        {Vendor: "postgresql", Product: "postgresql"},
	"postgresql-16":     {Vendor: "postgresql", Product: "postgresql"},
	"postgresql-15":     {Vendor: "postgresql", Product: "postgresql"},
	"postgresql-14":     {Vendor: "postgresql", Product: "postgresql"},
	"postgresql-13":     {Vendor: "postgresql", Product: "postgresql"},
	"postgresql-client": {Vendor: "postgresql", Product: "postgresql"},
	"mongodb":           {Vendor: "mongodb", Product: "mongodb"},
	"mongodb-org":       {Vendor: "mongodb", Product: "mongodb"},
	"mongosh":           {Vendor: "mongodb", Product: "mongodb"},
	"redis-server":      {Vendor: "redislabs", Product: "redis"},
	"redis":             {Vendor: "redislabs", Product: "redis"},
	"memcached":         {Vendor: "memcached", Product: "memcached"},
	"sqlite3":           {Vendor: "sqlite", Product: "sqlite"},
	"libsqlite3-0":      {Vendor: "sqlite", Product: "sqlite"},
	"cassandra":         {Vendor: "apache", Product: "cassandra"},
	"elasticsearch":     {Vendor: "elastic", Product: "elasticsearch"},

	// ---- Runtimes & Languages ----
	"python3":         {Vendor: "python_software_foundation", Product: "python"},
	"python3-minimal": {Vendor: "python_software_foundation", Product: "python"},
	"python3.11":      {Vendor: "python_software_foundation", Product: "python"},
	"python3.12":      {Vendor: "python_software_foundation", Product: "python"},
	"python3.13":      {Vendor: "python_software_foundation", Product: "python"},
	"nodejs":          {Vendor: "nodejs", Product: "node.js"},
	"nodejs-doc":      {Vendor: "nodejs", Product: "node.js"},
	"ruby":            {Vendor: "ruby-lang", Product: "ruby"},
	"ruby3.1":         {Vendor: "ruby-lang", Product: "ruby"},
	"php":             {Vendor: "php", Product: "php"},
	"php8.2":          {Vendor: "php", Product: "php"},
	"php8.3":          {Vendor: "php", Product: "php"},
	"php8.4":          {Vendor: "php", Product: "php"},
	"php-common":      {Vendor: "php", Product: "php"},
	"go":              {Vendor: "golang", Product: "go"},
	"golang":          {Vendor: "golang", Product: "go"},
	"golang-go":       {Vendor: "golang", Product: "go"},
	"openjdk-11-jre":  {Vendor: "oracle", Product: "openjdk"},
	"openjdk-11-jdk":  {Vendor: "oracle", Product: "openjdk"},
	"openjdk-17-jre":  {Vendor: "oracle", Product: "openjdk"},
	"openjdk-17-jdk":  {Vendor: "oracle", Product: "openjdk"},
	"openjdk-21-jre":  {Vendor: "oracle", Product: "openjdk"},
	"openjdk-21-jdk":  {Vendor: "oracle", Product: "openjdk"},
	"openjdk-22-jre":  {Vendor: "oracle", Product: "openjdk"},
	"default-jre":     {Vendor: "oracle", Product: "openjdk"},
	"default-jdk":     {Vendor: "oracle", Product: "openjdk"},
	"perl":            {Vendor: "perl", Product: "perl"},
	"perl-base":       {Vendor: "perl", Product: "perl"},
	"lua5.3":          {Vendor: "lua", Product: "lua"},
	"lua5.4":          {Vendor: "lua", Product: "lua"},

	// ---- Libraries ----
	"libc6":           {Vendor: "gnu", Product: "glibc"},
	"libc6-dev":       {Vendor: "gnu", Product: "glibc"},
	"glibc":           {Vendor: "gnu", Product: "glibc"},
	"libpam":          {Vendor: "linux-pam", Product: "linux_pam"},
	"libpam-modules":  {Vendor: "linux-pam", Product: "linux_pam"},
	"libpam0g":        {Vendor: "linux-pam", Product: "linux_pam"},
	"zlib1g":          {Vendor: "zlib", Product: "zlib"},
	"zlib":            {Vendor: "zlib", Product: "zlib"},
	"libxml2":         {Vendor: "xmlsoft", Product: "libxml2"},
	"libxslt1.1":      {Vendor: "xmlsoft", Product: "libxslt"},
	"libcurl4":        {Vendor: "haxx", Product: "curl"},
	"curl":            {Vendor: "haxx", Product: "curl"},
	"libcurl3-gnutls": {Vendor: "haxx", Product: "curl"},
	"wget":            {Vendor: "gnu", Product: "wget"},
	"libpcre3":        {Vendor: "pcre", Product: "pcre"},
	"libpng":          {Vendor: "libpng", Product: "libpng"},
	"libjpeg":         {Vendor: "libjpeg-turbo", Product: "libjpeg-turbo"},
	"libtiff":         {Vendor: "libtiff", Product: "libtiff"},
	"giflib":          {Vendor: "giflib", Product: "giflib"},
	"libgd3":          {Vendor: "libgd", Product: "libgd"},
	"freetype":        {Vendor: "freetype", Product: "freetype"},
	"fontconfig":      {Vendor: "fontconfig", Product: "fontconfig"},

	// ---- Shell & CLI Tools ----
	"bash":       {Vendor: "gnu", Product: "bash"},
	"dash":       {Vendor: "gnu", Product: "bash"},
	"zsh":        {Vendor: "zsh", Product: "zsh"},
	"git":        {Vendor: "git", Product: "git"},
	"git-man":    {Vendor: "git", Product: "git"},
	"sudo":       {Vendor: "sudo_project", Product: "sudo"},
	"vim":        {Vendor: "vim", Product: "vim"},
	"vim-tiny":   {Vendor: "vim", Product: "vim"},
	"neovim":     {Vendor: "neovim", Product: "neovim"},
	"nano":       {Vendor: "gnu", Product: "nano"},
	"tmux":       {Vendor: "tmux", Product: "tmux"},
	"screen":     {Vendor: "gnu", Product: "screen"},
	"rsync":      {Vendor: "rsync", Product: "rsync"},
	"tar":        {Vendor: "gnu", Product: "tar"},
	"gzip":       {Vendor: "gnu", Product: "gzip"},
	"xz-utils":   {Vendor: "tukaani", Product: "xz"},
	"bzip2":      {Vendor: "bzip", Product: "bzip2"},
	"zip":        {Vendor: "info-zip", Product: "zip"},
	"unzip":      {Vendor: "info-zip", Product: "unzip"},
	"sed":        {Vendor: "gnu", Product: "sed"},
	"grep":       {Vendor: "gnu", Product: "grep"},
	"awk":        {Vendor: "gnu", Product: "gawk"},
	"gawk":       {Vendor: "gnu", Product: "gawk"},
	"findutils":  {Vendor: "gnu", Product: "findutils"},
	"coreutils":  {Vendor: "gnu", Product: "coreutils"},
	"util-linux": {Vendor: "kernel", Product: "util-linux"},
	"cron":       {Vendor: "isc", Product: "cron"},
	"logrotate":  {Vendor: "logrotate", Product: "logrotate"},

	// ---- Containers & Orchestration ----
	"docker-ce":      {Vendor: "docker", Product: "docker"},
	"docker.io":      {Vendor: "docker", Product: "docker"},
	"docker-cli":     {Vendor: "docker", Product: "docker"},
	"containerd":     {Vendor: "docker", Product: "containerd"},
	"runc":           {Vendor: "docker", Product: "runc"},
	"kubectl":        {Vendor: "kubernetes", Product: "kubernetes"},
	"kubelet":        {Vendor: "kubernetes", Product: "kubernetes"},
	"kubeadm":        {Vendor: "kubernetes", Product: "kubernetes"},
	"kubearmor":      {Vendor: "kubearmor", Product: "kubearmor"},
	"podman":         {Vendor: "containers", Product: "podman"},
	"podman-compose": {Vendor: "containers", Product: "podman"},
	"lxc":            {Vendor: "linuxcontainers", Product: "lxc"},
	"lxd":            {Vendor: "linuxcontainers", Product: "lxd"},
	"vagrant":        {Vendor: "hashicorp", Product: "vagrant"},

	// ---- Monitoring & Logging ----
	"prometheus":     {Vendor: "prometheus", Product: "prometheus"},
	"node-exporter":  {Vendor: "prometheus", Product: "node_exporter"},
	"grafana":        {Vendor: "grafana", Product: "grafana"},
	"grafana-server": {Vendor: "grafana", Product: "grafana"},
	"telegraf":       {Vendor: "influxdata", Product: "telegraf"},
	"influxdb":       {Vendor: "influxdata", Product: "influxdb"},
	"kibana":         {Vendor: "elastic", Product: "kibana"},
	"logstash":       {Vendor: "elastic", Product: "logstash"},
	"nagios":         {Vendor: "nagios", Product: "nagios"},
	"nagios-plugins": {Vendor: "nagios", Product: "nagios"},

	// ---- DNS & Networking ----
	"bind9":           {Vendor: "isc", Product: "bind"},
	"bind":            {Vendor: "isc", Product: "bind"},
	"dnsmasq":         {Vendor: "the_kroehler_foundation", Product: "dnsmasq"},
	"unbound":         {Vendor: "nlnet_labs", Product: "unbound"},
	"isc-dhcp-server": {Vendor: "isc", Product: "dhcp"},
	"isc-dhcp-client": {Vendor: "isc", Product: "dhcp"},
	"frr":             {Vendor: "frr", Product: "frr"},
	"quagga":          {Vendor: "quagga", Product: "quagga"},
	"bird":            {Vendor: "bird", Product: "bird"},
	"strongswan":      {Vendor: "strongswan", Product: "strongswan"},
	"ipsec-tools":     {Vendor: "ipsec-tools", Product: "ipsec-tools"},
	"wireguard":       {Vendor: "wireguard", Product: "wireguard"},
	"openvpn":         {Vendor: "openvpn", Product: "openvpn"},
	"netplan.io":      {Vendor: "netplan", Product: "netplan"},

	// ---- Mail ----
	"postfix":       {Vendor: "postfix", Product: "postfix"},
	"sendmail":      {Vendor: "sendmail", Product: "sendmail"},
	"exim4":         {Vendor: "exim", Product: "exim"},
	"dovecot-core":  {Vendor: "dovecot", Product: "dovecot"},
	"dovecot-imapd": {Vendor: "dovecot", Product: "dovecot"},
	"courier":       {Vendor: "courier", Product: "courier"},

	// ---- Samba / File Sharing ----
	"samba":             {Vendor: "samba", Product: "samba"},
	"smbclient":         {Vendor: "samba", Product: "samba"},
	"nfs-common":        {Vendor: "linux", Product: "linux_kernel"},
	"nfs-kernel-server": {Vendor: "linux", Product: "linux_kernel"},
	"vsftpd":            {Vendor: "vsftpd", Product: "vsftpd"},
	"proftpd":           {Vendor: "proftpd", Product: "proftpd"},

	// ---- SCM & CI/CD ----
	"jenkins":       {Vendor: "jenkins", Product: "jenkins"},
	"gitlab-ce":     {Vendor: "gitlab", Product: "gitlab"},
	"gitlab-runner": {Vendor: "gitlab", Product: "gitlab"},
	"ansible":       {Vendor: "ansible", Product: "ansible"},
	"ansible-core":  {Vendor: "ansible", Product: "ansible"},
	"terraform":     {Vendor: "hashicorp", Product: "terraform"},
	"puppet":        {Vendor: "puppet", Product: "puppet"},
	"chef":          {Vendor: "chef", Product: "chef"},

	// ---- Message Queues ----
	"rabbitmq-server": {Vendor: "pivotal_software", Product: "rabbitmq"},
	"activemq":        {Vendor: "apache", Product: "activemq"},
	"kafka":           {Vendor: "apache", Product: "kafka"},
	"zookeeper":       {Vendor: "apache", Product: "zookeeper"},

	// ---- Virtualisation ----
	"qemu-system-x86": {Vendor: "qemu", Product: "qemu"},
	"qemu-system-arm": {Vendor: "qemu", Product: "qemu"},
	"qemu-kvm":        {Vendor: "qemu", Product: "qemu"},
	"libvirt-daemon":  {Vendor: "libvirt", Product: "libvirt"},
	"libvirt":         {Vendor: "libvirt", Product: "libvirt"},
	"virt-manager":    {Vendor: "virt-manager", Product: "virt-manager"},
	"virtualbox":      {Vendor: "oracle", Product: "virtualbox"},
	"virtualbox-dkms": {Vendor: "oracle", Product: "virtualbox"},
	"vmware":          {Vendor: "vmware", Product: "workstation"},

	// ---- X / Display ----
	"xserver-xorg-core": {Vendor: "x", Product: "x.org"},
	"xserver-xorg":      {Vendor: "x", Product: "x.org"},
	"xorg":              {Vendor: "x", Product: "x.org"},
	"wayland":           {Vendor: "wayland", Product: "wayland"},
	"libwayland":        {Vendor: "wayland", Product: "wayland"},

	// ---- Compression / Archiving ----
	"libarchive13": {Vendor: "libarchive", Product: "libarchive"},
	"p7zip":        {Vendor: "7-zip", Product: "7-zip"},
	"7zip":         {Vendor: "7-zip", Product: "7-zip"},
	"unrar":        {Vendor: "rar_labs", Product: "unrar"},

	// ---- Multimedia ----
	"ffmpeg":     {Vendor: "ffmpeg", Product: "ffmpeg"},
	"libavcodec": {Vendor: "ffmpeg", Product: "ffmpeg"},
	"vlc":        {Vendor: "videolan", Product: "vlc_media_player"},
	"vlc-bin":    {Vendor: "videolan", Product: "vlc_media_player"},
	"libvlc":     {Vendor: "videolan", Product: "vlc_media_player"},
	"gstreamer":  {Vendor: "gstreamer", Product: "gstreamer"},
	"blender":    {Vendor: "blender", Product: "blender"},

	// ---- Security Tools ----
	"nmap":        {Vendor: "nmap", Product: "nmap"},
	"wireshark":   {Vendor: "wireshark", Product: "wireshark"},
	"metasploit":  {Vendor: "rapid7", Product: "metasploit"},
	"burpsuite":   {Vendor: "portswigger", Product: "burp_suite"},
	"nikto":       {Vendor: "cirt", Product: "nikto"},
	"hydra":       {Vendor: "vanhauser", Product: "hydra"},
	"john":        {Vendor: "openwall", Product: "john_the_ripper"},
	"sqlmap":      {Vendor: "sqlmap", Product: "sqlmap"},
	"aircrack-ng": {Vendor: "aircrack-ng", Product: "aircrack-ng"},

	// ---- Common Utilities ----
	"dbus":           {Vendor: "freedesktop", Product: "dbus"},
	"policykit-1":    {Vendor: "freedesktop", Product: "policykit"},
	"polkitd":        {Vendor: "freedesktop", Product: "policykit"},
	"avahi":          {Vendor: "avahi", Product: "avahi"},
	"cups":           {Vendor: "apple", Product: "cups"},
	"bluez":          {Vendor: "bluez", Product: "bluez"},
	"NetworkManager": {Vendor: "gnome", Product: "networkmanager"},
	"iwd":            {Vendor: "iwd", Product: "iwd"},
	"chrony":         {Vendor: "chrony", Product: "chrony"},
	"ntp":            {Vendor: "ntp", Product: "ntp"},
	"ntpsec":         {Vendor: "ntp", Product: "ntp"},
}

// LookupVendorProduct attempts to resolve a package name to a CPE vendor/product
// pair. Returns the entry if found, or nil if the package is not in the map.
func LookupVendorProduct(pkgName string) *VendorEntry {
	if e, ok := packageVendorMap[pkgName]; ok {
		return &VendorEntry{Vendor: e.Vendor, Product: e.Product}
	}
	return nil
}
