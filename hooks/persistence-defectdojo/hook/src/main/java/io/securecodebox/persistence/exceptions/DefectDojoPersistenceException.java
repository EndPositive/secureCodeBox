// SPDX-FileCopyrightText: 2021 iteratec GmbH
//
// SPDX-License-Identifier: Apache-2.0
package io.securecodebox.persistence.exceptions;

public class DefectDojoPersistenceException extends RuntimeException {
  public DefectDojoPersistenceException(String message) {
    super(message);
  }

  public DefectDojoPersistenceException(String message, Throwable cause) {
    super(message, cause);
  }
}
