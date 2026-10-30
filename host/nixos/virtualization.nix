# KVM-Sentinel-SOC — NixOS hypervisor module
#
# Import this module from /etc/nixos/configuration.nix:
#
#   imports = [ ./host/nixos/virtualization.nix ];
#   kvmSentinel = {
#     enable = true;
#     user = "yourlogin";          # added to the libvirtd and kvm groups
#   };
#
# What it does:
#   * KVM/QEMU + libvirtd with the `qemu:///system` connection,
#   * the userspace tools used by host/provisioning/*.sh,
#   * IPv4 forwarding and the nftables rules needed for the classroom
#     "live fire" DNAT (2222 -> 10.10.0.10:2222) and the approval webhook (5000).
#
# What it deliberately does NOT do:
#   * it does not declare the `default` NAT network (libvirt ships it),
#   * it does not declare `backend-isolated`: that network is defined from
#     host/networks/backend-isolated.xml by deploy-lab.sh so that the exact same
#     XML is used on NixOS, Debian/Ubuntu and WSL2 hosts.
{ config, lib, pkgs, ... }:

let
  cfg = config.kvmSentinel;
in
{
  options.kvmSentinel = {
    enable = lib.mkEnableOption "the KVM-Sentinel-SOC hypervisor lab";

    user = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "alice";
      description = ''
        Existing login that should be able to talk to qemu:///system
        (member of the libvirtd and kvm groups). Leave null when the
        administrator is managed elsewhere.
      '';
    };

    liveFirePort = lib.mkOption {
      type = lib.types.port;
      default = 2222;
      description = "TCP port on the physical host that is DNAT-ed to the honeypot SSH service.";
    };

    controllerPort = lib.mkOption {
      type = lib.types.port;
      default = 5000;
      description = "TCP port of host/controller/approval_daemon.py (alert webhook).";
    };

    labRoot = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/kvm-sentinel";
      description = "State directory for lab artefacts (images, seeds, audit logs).";
    };
  };

  config = lib.mkIf cfg.enable {
    # ---------------------------------------------------------------- kernel
    # kvm-intel: the target host is a Core i7-1160G7 (Tiger Lake).
    # vhost_net: keeps virtio-net processing out of the QEMU main loop, which
    # matters when 4 vCPUs of a 4c/8t laptop are given to vm-soc.
    boot.kernelModules = [ "kvm-intel" "tun" "vhost_net" "bridge" "br_netfilter" ];
    boot.kernel.sysctl = {
      "net.ipv4.ip_forward" = 1;
      # Let the bridge be transparent for iptables: the live-fire DNAT and the
      # MASQUERADE rule in enable-live-fire.sh rely on seeing bridged frames.
      "net.bridge.bridge-nf-call-iptables" = 1;
    };

    # ------------------------------------------------------------- libvirt
    virtualisation.libvirtd = {
      enable = true;
      qemu = {
        package = pkgs.qemu_kvm;
        runAsRoot = true;
        # swtpm is optional for this lab but keeps Windows/TPM guests possible
        # later without touching the module again.
        swtpm.enable = true;
      };
      onBoot = "start";
      onShutdown = "shutdown";
    };

    programs.virt-manager.enable = true;

    # ------------------------------------------------------------- accounts
    users.groups.libvirtd.members = lib.mkIf (cfg.user != null) [ cfg.user ];
    users.users = lib.mkIf (cfg.user != null) {
      "${cfg.user}".extraGroups = [ "libvirtd" "kvm" ];
    };

    # ------------------------------------------------------------ firewall
    networking.firewall = {
      # 2222 : classroom live-fire entry point (DNAT-ed to the honeypot)
      # 5000 : approval daemon webhook, called from vm-soc (192.168.122.20)
      allowedTCPPorts = [ cfg.liveFirePort cfg.controllerPort ];

      # Traffic inside the two libvirt bridges is host-managed; do not let the
      # NixOS firewall second-guess libvirt's own rules.
      trustedInterfaces = [ "virbr0" "virbr1" ];

      # When the classroom forward is enabled, NixOS uses nftables while
      # enable-live-fire.sh speaks iptables-nft. Explicit accepts keep both
      # worlds consistent (see docs/01-INSTALL-NIXOS.md).
      extraForwardRules = ''
        iifname { "virbr0", "virbr1" } accept
        oifname { "virbr0", "virbr1" } ct state established,related accept
        ip daddr 10.10.0.10 tcp dport 2222 accept
      '';
    };

    # --------------------------------------------------------------- tooling
    environment.systemPackages = with pkgs; [
      libvirt
      virtinst             # virt-install — deploy-lab.sh preflights it
      virt-manager
      qemu_kvm
      cloud-utils          # cloud-localds
      cdrkit               # genisoimage fallback
      iptables
      iproute2
      curl
      wget
      jq
      openssh
      socat
      tcpdump
      (python3.withPackages (ps: [ ps.requests ps.flask ps.rich ]))
    ];

    # Keep lab artefacts on a predictable, world-readable-by-admin path.
    systemd.tmpfiles.rules = [
      "d ${cfg.labRoot} 0775 root root -"
    ];

    # A short reminder in the login banner of the hypervisor host.
    environment.etc."motd.d/kvm-sentinel".text = ''
      KVM-Sentinel-SOC lab host
        deploy        : sudo ./host/provisioning/deploy-lab.sh
        classroom     : sudo ./host/provisioning/enable-live-fire.sh enable
        controller    : sudo python3 host/controller/approval_daemon.py
        teardown      : sudo ./host/provisioning/cleanup-lab.sh
    '';
  };
}
