// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.tron.keystore.WalletUtils;
import org.tron.common.utils.StringUtil;

/** Read-only adapter to the pinned client's native keystore authentication. */
public final class ErpcTronKey {
  public static void main(String[] args) {
    byte[] input = new byte[1025];
    int status = 0;
    try {
      if (args.length != 1) throw new IllegalArgumentException();
      int size = 0;
      int next;
      while ((next = System.in.read()) != -1) {
        if (size == input.length) throw new IllegalArgumentException();
        input[size++] = (byte) next;
      }
      if (size > 0 && input[size - 1] == '\n') size--;
      String password = new String(input, 0, size, StandardCharsets.UTF_8);
      if (size > 1024 || password.length() < 6 || password.indexOf('\n') >= 0
          || password.indexOf('\r') >= 0 || password.indexOf('\0') >= 0
          || password.startsWith("\uFEFF")) throw new IllegalArgumentException();
      // No node, wallet account or transaction is started. The native V3 loader
      // authenticates the MAC, decrypts and checks the declared address itself.
      byte[] address = WalletUtils.loadCredentials(password, new File(args[0]), true)
          .getSignInterface().getAddress();
      System.out.println(StringUtil.encode58Check(address));
    } catch (Throwable ignored) {
      // Native exceptions can contain caller-provided values. Never echo them.
      System.err.println("TRON keystore validation failed");
      status = 1;
    } finally {
      Arrays.fill(input, (byte) 0);
    }
    if (status != 0) System.exit(status);
  }
}
