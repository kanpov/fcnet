use tokio_tun::TunBuilder;

use crate::{get_link_index, run_iptables, Cli};

pub async fn run(cli: &Cli, netlink_handle: &rtnetlink::Handle) {
    if cli.operation_group.add {
        add_without_netns(&cli, &netlink_handle).await;
    } else if cli.operation_group.del {
        del_without_netns(&cli, &netlink_handle).await;
    } else {
        check_without_netns(&cli, &netlink_handle).await;
    }
}

async fn add_without_netns(cli: &Cli, netlink_handle: &rtnetlink::Handle) {
    TunBuilder::new()
        .name(&cli.tap_name)
        .tap(true)
        .persist()
        .up()
        .try_build()
        .expect("Could not create tap device");
    let tap_idx = get_link_index(cli.tap_name.clone(), netlink_handle).await;
    netlink_handle
        .address()
        .add(tap_idx, cli.tap_ip.address(), cli.tap_ip.network_length())
        .execute()
        .await
        .expect("Could not assign IP to tap device");

    run_iptables(cli, format!("-t nat -A POSTROUTING -o {} -j MASQUERADE", cli.iface_name)).await;
    run_iptables(
        cli,
        "-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT".to_string(),
    )
    .await;
    run_iptables(cli, format!("-A FORWARD -i {} -o {} -j ACCEPT", cli.tap_name, cli.iface_name)).await;
}

async fn del_without_netns(cli: &Cli, netlink_handle: &rtnetlink::Handle) {
    let tap_idx = get_link_index(cli.tap_name.clone(), netlink_handle).await;
    netlink_handle
        .link()
        .del(tap_idx)
        .execute()
        .await
        .expect("Could not delete tap device");

    run_iptables(cli, format!("-t nat -D POSTROUTING -o {} -j MASQUERADE", cli.iface_name)).await;
    run_iptables(
        cli,
        "-D FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT".to_string(),
    )
    .await;
    run_iptables(cli, format!("-D FORWARD -i {} -o {} -j ACCEPT", cli.tap_name, cli.iface_name)).await;
}

async fn check_without_netns(cli: &Cli, netlink_handle: &rtnetlink::Handle) {
    get_link_index(cli.tap_name.clone(), netlink_handle).await;

    run_iptables(cli, format!("-t nat -C POSTROUTING -o {} -j MASQUERADE", cli.iface_name)).await;
    run_iptables(
        cli,
        "-C FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT".to_string(),
    )
    .await;
    run_iptables(cli, format!("-C FORWARD -i {} -o {} -j ACCEPT", cli.tap_name, cli.iface_name)).await;
}
