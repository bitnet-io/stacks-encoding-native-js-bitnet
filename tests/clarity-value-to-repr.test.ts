import { decodeClarityValueToRepr } from '../';

test('decode clarity value to repr string - optional', () => {
  const repr = decodeClarityValueToRepr('0x0a010000000000000000000000116c7a7446');
  expect(repr).toBe('(some u74834408518)');
});

test('decode clarity value to repr string - list', () => {
  const repr = decodeClarityValueToRepr('0x0b000000640100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d400100000000000000000000000000c65d40');
  expect(repr).toEqual('(list u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000 u13000000)');
});

test('decode clarity value to repr string from Buffer', () => {
  const repr = decodeClarityValueToRepr(Buffer.from('0a010000000000000000000000116c7a7446', 'hex'));
  expect(repr).toBe('(some u74834408518)');
});
