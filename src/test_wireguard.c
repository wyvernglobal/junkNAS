/*
 * junkNAS - WireGuard peer connectivity test harness
 *
 * This is a simple test program to verify:
 *  - WireGuard keys can be generated
 *  - Peer endpoints and allowed IPs can be wired up
 *  - Two peers reference each other via allowed IPs
 */

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "wireguard.h"

static void init_allowed_ip(wg_allowedip *allowedip, const char *ip, uint8_t cidr) {
    memset(allowedip, 0, sizeof(*allowedip));
    allowedip->family = AF_INET;
    allowedip->cidr = cidr;
    inet_pton(AF_INET, ip, &allowedip->ip4);
}

static void init_peer(wg_peer *peer,
                      const char *endpoint_ip,
                      uint16_t endpoint_port,
                      wg_allowedip *allowedip,
                      const char *allowed_ip) {
    wg_key private_key;

    memset(peer, 0, sizeof(*peer));
    wg_generate_private_key(private_key);
    wg_generate_public_key(peer->public_key, private_key);
    wg_generate_preshared_key(peer->preshared_key);
    peer->flags = WGPEER_HAS_PUBLIC_KEY | WGPEER_HAS_PRESHARED_KEY;

    peer->endpoint.addr4.sin_family = AF_INET;
    peer->endpoint.addr4.sin_port = htons(endpoint_port);
    inet_pton(AF_INET, endpoint_ip, &peer->endpoint.addr4.sin_addr);

    init_allowed_ip(allowedip, allowed_ip, 32);
    peer->first_allowedip = allowedip;
    peer->last_allowedip = allowedip;
}

static bool peer_has_allowed_ip(const wg_peer *peer, const struct in_addr *ip, uint8_t cidr) {
    const wg_allowedip *allowedip = NULL;

    wg_for_each_allowedip(peer, allowedip) {
        if (allowedip->family != AF_INET) {
            continue;
        }

        if (allowedip->cidr == cidr &&
            memcmp(&allowedip->ip4, ip, sizeof(*ip)) == 0) {
            return true;
        }
    }

    return false;
}

static int test_peer_connection(const wg_peer *peer_a,
                                const wg_peer *peer_b,
                                const struct in_addr *peer_a_ip,
                                const struct in_addr *peer_b_ip) {
    if (wg_key_is_zero(peer_a->public_key) || wg_key_is_zero(peer_b->public_key)) {
        fprintf(stderr, "Peer public keys are missing.\n");
        return 1;
    }

    if (peer_a->endpoint.addr.sa_family != AF_INET ||
        peer_b->endpoint.addr.sa_family != AF_INET) {
        fprintf(stderr, "Peer endpoints are not IPv4.\n");
        return 1;
    }

    if (!peer_has_allowed_ip(peer_a, peer_b_ip, 32)) {
        fprintf(stderr, "Peer A does not allow Peer B's IP.\n");
        return 1;
    }

    if (!peer_has_allowed_ip(peer_b, peer_a_ip, 32)) {
        fprintf(stderr, "Peer B does not allow Peer A's IP.\n");
        return 1;
    }

    return 0;
}

int main(void) {
    wg_peer peer_a;
    wg_peer peer_b;
    wg_allowedip allowedip_a;
    wg_allowedip allowedip_b;
    struct in_addr peer_a_ip;
    struct in_addr peer_b_ip;

    inet_pton(AF_INET, "10.99.0.1", &peer_a_ip);
    inet_pton(AF_INET, "10.99.0.2", &peer_b_ip);

    init_peer(&peer_a, "192.0.2.1", 51820, &allowedip_a, "10.99.0.2");
    init_peer(&peer_b, "192.0.2.2", 51821, &allowedip_b, "10.99.0.1");

    if (test_peer_connection(&peer_a, &peer_b, &peer_a_ip, &peer_b_ip) != 0) {
        fprintf(stderr, "WireGuard peer connection test failed.\n");
        return 1;
    }

    printf("WireGuard peer connection test passed.\n");
    return 0;
}
