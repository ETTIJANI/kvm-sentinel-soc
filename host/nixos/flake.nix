{
  description = "KVM-Sentinel-SOC — host tooling for the hypervisor-integrated AI SOC lab";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      # Import this from configuration.nix: imports = [ kvm-sentinel.nixosModules.default ];
      nixosModules.default = ./virtualization.nix;

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          name = "kvm-sentinel-soc";

          packages = with pkgs; [
            libvirt
            virt-manager
            qemu_kvm
            cloud-utils        # cloud-localds
            cdrkit             # genisoimage (fallback for cloud-localds)
            iptables
            iproute2
            curl
            wget
            jq
            openssh
            socat
            shellcheck
            (python3.withPackages (ps: [ ps.requests ps.flask ps.rich ]))
          ];

          shellHook = ''
            echo ""
            echo "  KVM-Sentinel-SOC dev shell"
            echo "  --------------------------"
            echo "  1. deploy the lab      : sudo ./host/provisioning/deploy-lab.sh"
            echo "  2. start the controller: sudo python3 host/controller/approval_daemon.py"
            echo "  3. open the classroom  : sudo ./host/provisioning/enable-live-fire.sh enable"
            echo "  4. SOC dashboard       : http://192.168.122.20:3000  (admin/sentinel)"
            echo ""
            echo "  virsh -c qemu:///system list --all"
            echo ""
          '';
        };
      });
    };
}
