# nixos module for I405

i405Packages:

{ config, pkgs, lib, ... }:

let inherit (lib) types;

    packageOption = lib.mkOption {
      type = types.package;
      default = i405Packages.${pkgs.system}.default;
      description = "I405 package to use";
    };

    commonOptions = {
      package = packageOption;
      listenHost = lib.mkOption {
        type = types.nullOr types.str;
        default = null;
        defaultText = "(delegated to I405)";
        example = "0.0.0.0:1405";
        description = "Host and port to bind to.";
      };
      # TODO support making this a file so that it's possible to use agenix etc
      password = lib.mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "correct horse battery staple";
        description = "Pre-shared key (password), must be same on client and server";
      };
      tunIpv4 = lib.mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "192.168.99.1/24";
        description = "IP addresses to assign to the tunnel";
      };
      extraArgs = lib.mkOption {
        type = types.listOf types.str;
        default = [];
        example = ''
          ["--tun-name" "my-tun0"]
        '';
        description = "Additional CLI arguments.";
      };
    };

    commonAssertions = cfg: [
      {
        assertion = cfg.password != null;
        message = "password option is required";
      }
    ];

    commonSystemdService = {
      # TODO should this actually be put earlier, since I405-tunnel is kinda part of the network?
      wantedBy = [ "multi-user.target" ];
      path = [ pkgs.iproute2 ];
      startLimitIntervalSec = 90;
      startLimitBurst = 4;
      serviceConfig = {
        Restart = "on-failure";

        # inspired by the Navidrome module
        RestrictNamespaces = true;
        ProtectHome = true;
        ProtectControlGroups = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectHostname = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        # there's more you could add here, like `chroot`ing, but at least for now I want it to be
        # easy to be able to monitor packets.
      };
    };

    commonCliArgs = cfg: (
      ["--password" cfg.password]
      ++ lib.optionals (cfg.listenHost != null) ["--listen-host" cfg.listenHost]
      ++ lib.optionals (cfg.tunIpv4 != null) ["--tun-ipv4" cfg.tunIpv4]
      ++ cfg.extraArgs
    );

    xorNullables = b1: b2: (b1 == null && b2 != null) || (b1 != null && b2 == null);
in

{
  options.services = {
    i405-tunnel-server = commonOptions // {
      enable = lib.mkEnableOption "Enable I405 tunnel server";
    };

    i405-tunnel-client = commonOptions // {
      enable = lib.mkEnableOption "Enable I405 tunnel client";

      peer = lib.mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "my-server.com:1405";
        description = "Address and port of server to connect to.";
      }; # Added semicolon here

      outgoingSpeed = lib.mkOption {
        type = types.nullOr types.str;
        default = null;
        defaultText = "(either this or outgoingPacketInterval is required)";
        example = "100k";
        description = "Average outgoing speed in bytes/second, visible by network observers.";
      };

      incomingSpeed = lib.mkOption {
        type = types.nullOr types.str;
        default = null;
        defaultText = "(required when enabled is set)";
        example = "100k";
        description = "Average incoming speed in bytes/second, visible by network observers."; # Added semicolon here
      };

      outgoingPacketInterval = lib.mkOption {
        type = types.nullOr types.str;
        default = null;
        defaultText = "(either this or outgoingSpeed is required)";
        example = "10ms";
        description = "Average outgoing packet interval, as a time unit. Visible by network observers";
      };

      incomingPacketInterval = lib.mkOption {
        type = types.nullOr types.str;
        default = null;
        defaultText = "(either this or incomingSpeed is required)";
        example = "10ms";
        description = "Average incoming packet interval, as a time unit. Visible by network observers";
      };
    };
  };

  config = lib.mkMerge [
    # Server:
    (let cfg = config.services.i405-tunnel-server; in
     lib.mkIf cfg.enable {
       assertions = commonAssertions cfg;

       systemd.services.i405-tunnel-server = lib.mkMerge [
         commonSystemdService
         {
           description = "I405-Tunnel Server";
           after = [ "network.target" ];  # generally will be good enough for our bind IP to be assigned
           # it's simple enough to use ExecStart, but I know there are some weird escaping rules
           # applied to ExecStart that I'd rather avoid.
           script = let allArgs = ["server"] ++ commonCliArgs cfg;
                    in "${cfg.package}/bin/i405-tunnel ${lib.escapeShellArgs allArgs}";
         }
       ];
     })

    # Client:
    (let cfg = config.services.i405-tunnel-client; in
     lib.mkIf cfg.enable {
       assertions = lib.mkMerge [
         (commonAssertions cfg)
         [
           {
             assertion = cfg.peer != null;
             message = "The `peer` option is required";
           }
           {
             assertion = xorNullables cfg.incomingSpeed cfg.incomingPacketInterval;
             message = "Exactly one of incomingSpeed and incomingPacketInterval must be set";
           }
           {
             assertion = xorNullables cfg.outgoingSpeed cfg.outgoingPacketInterval;
             message = "Exactly one of outgoingSpeed and outgoingPacketInterval must be set";
           }
         ]
      ];

      systemd.services.i405-tunnel-client = lib.mkMerge [
        commonSystemdService
        {
          description = "I405-Tunnel Client";
          # unlike the server, we want to wait until we can actually connect to the server before attempting to do so
          after = [ "network-online.target" ];
          wants = [ "network-online.target" ];
          script = let allArgs = (
            ["client"]
            ++ ["--peer" cfg.peer]
            ++ lib.optionals (cfg.outgoingSpeed != null) ["--outgoing-speed" cfg.outgoingSpeed]
            ++ lib.optionals (cfg.incomingSpeed != null) ["--incoming-speed" cfg.incomingSpeed]
            ++ lib.optionals (cfg.outgoingPacketInterval != null) ["--outgoing-packet-interval" cfg.outgoingPacketInterval]
            ++ lib.optionals (cfg.incomingPacketInterval != null) ["--incoming-packet-interval" cfg.incomingPacketInterval]
            ++ commonCliArgs cfg
          ); in "${cfg.package}/bin/i405-tunnel ${lib.escapeShellArgs allArgs}";
        }
      ];
     })
  ];
}
