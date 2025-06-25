{ pkgs }: {
  deps = [
    pkgs.python311
    pkgs.sqlite
  ];

  env = {
    FLASK_APP = "main.py";
    FLASK_RUN_PORT = "8080";
    FLASK_RUN_HOST = "0.0.0.0";
  };

  packages = [
    pkgs.python311Packages.pip
  ];

  postBuild = ''
    pip install flask flask-cors
  '';
}
