/**
 * Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved
 */

import React from 'react';
import {Col, Spinner} from 'react-bootstrap';

export default function Loader(): JSX.Element {
  return (
    <Col>
      <h5>
        <Spinner
          style={{verticalAlign: 'middle'}}
          className="mr-2"
          animation="border"
          variant="primary"
        />
        Loading...
      </h5>
    </Col>
  );
}
