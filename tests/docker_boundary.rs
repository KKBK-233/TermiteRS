use std::fs;

use serde_yaml::Value;

/// Docker 默认入口必须保持只读；维护权限只能通过单独服务显式取得。
#[test]
fn default_service_does_not_mount_repository_writable_or_expose_ssh() {
    let compose =
        fs::read_to_string(format!("{}/docker-compose.yml", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let document: Value = serde_yaml::from_str(&compose).unwrap();
    let common = &document["x-termiters-common"];
    assert_eq!(common["read_only"].as_bool(), Some(true));
    assert!(sequence(common, "cap_drop").contains(&"ALL"));
    assert!(sequence(common, "security_opt").contains(&"no-new-privileges:true"));

    let observer = &document["services"]["termiters"];
    let observer_volumes = sequence(observer, "volumes");
    assert!(
        observer_volumes
            .iter()
            .any(|item| item.ends_with(":/workspace/project:ro"))
    );
    assert!(observer_volumes.iter().all(|item| !item.contains("/.ssh")));

    let maintainer = &document["services"]["termiters-maintainer"];
    assert!(sequence(maintainer, "profiles").contains(&"maintainer"));
    let maintainer_volumes = sequence(maintainer, "volumes");
    assert!(
        maintainer_volumes
            .iter()
            .any(|item| item.ends_with(":/workspace/project"))
    );
    assert!(
        maintainer_volumes
            .iter()
            .any(|item| item.ends_with(":/root/.ssh:ro"))
    );
}

fn sequence<'a>(value: &'a Value, key: &str) -> Vec<&'a str> {
    value[key]
        .as_sequence()
        .unwrap()
        .iter()
        .map(|item| item.as_str().unwrap())
        .collect()
}
