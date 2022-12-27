package org.azidp4j.authorize.request;

import java.util.function.Supplier;
import org.azidp4j.authorize.response.RedirectTo;

public interface RedirectToSupplier extends Supplier<RedirectTo> {}
