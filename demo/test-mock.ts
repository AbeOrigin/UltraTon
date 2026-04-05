import { mock, test } from 'node:test';
import https from 'node:https';

test('mock test', () => {
    const fake = () => console.log('faked');
    mock.method(https, 'request', fake);
    (https as any).request('dummy');
});
